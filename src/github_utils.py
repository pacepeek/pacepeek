from flask import session
import random,re,json, tiktoken
from flask_login import current_user
import sqlalchemy
from sqlalchemy.exc import SQLAlchemyError
from requests.exceptions import RequestException
import logging
import time
import string
from zoneinfo import ZoneInfo
from pprint import pprint
from . import config,db
from .models import (User, Post, Commit, Repo, Branch, Notification)

from .llms import gpt_generate_summary_for_user_commits_openai, gpt_generate_summary_for_user_commits_groq, gpt_generate_summary_for_user_commits_local, gpt_judge_with_openai, gpt_judge_with_groq, gpt_judge_with_local, gpt_judge_with_anthropic

from .utils import GPTCreateSummaryError, create_admin_notification, log_the_error_context, create_user_notification

from .x_utils import post_to_x
import requests
from datetime import datetime, timezone
from jwt import JWT, jwk_from_pem

MAX_RETRIES = 3  # Maximum number of retries for each operation
RETRY_DELAY = 5  # Delay between retries in seconds

logging.basicConfig(level=logging.INFO)


class FetchCommitDataError(Exception):
    pass


class CreatePostDataError(Exception):
    pass

class PostPostError(Exception):
    pass


def to_naive_utc(dt: datetime) -> datetime:
    # this is for storing dates into db as naive utc
    # Convert the timezone-aware datetime object to UTC
    utc_dt = dt.astimezone(ZoneInfo('UTC'))
    # Return a naive datetime (without timezone information)
    return utc_dt.replace(tzinfo=None)

def parse_to_utc_from_github_iso(timestamp_str: str) -> datetime:
    # Parse the timestamp from GitHub like: '2023-10-12T20:40:04+03:00'
    try: 
        timestamp_obj = datetime.fromisoformat(timestamp_str)
        # Convert the timestamp to UTC
        return timestamp_obj.replace(tzinfo=ZoneInfo('UTC'))
    except ValueError:
        raise ValueError(f"Failed to parse timestamp {timestamp_str} from GitHub") from None


def delete_user_profile(user: User):
    """
    deletes users profile, along with all the posts and commits.
    removes user repo webhooks
    deletes user repos and their branches and filetypes
    deletes user notifications
    deletes user settings
    deletes the github app if installed
    TODO removes also stripe billing thing when we have it
    """
    logging.info(f"deleting user profile for {user.github_login}")
    try:
        logging.info(f"deleting user posts for {user.github_login}")
        posts = Post.query.filter_by(author_github_id=user.github_id).all()
        for post in posts:
            db.session.delete(post)
        logging.info(f"deleting user commits for {user.github_login}")
        commits = Commit.query.filter_by(author_github_id=user.github_id).all()
        for commit in commits:
            db.session.delete(commit)
        # delete user repos and their branches and filetypes
        logging.info(f"deleting user repos for {user.github_login}")
        repos = Repo.query.filter_by(owner_github_id=user.github_id).all()
        for repo in repos:
            for branch in repo.branches:
                db.session.delete(branch)
            for filetype in repo.filetypes:
                db.session.delete(filetype)
            if repo.webhook_active:
                logging.info(f"deactivating webhook for {repo.name}")
                deactivate_webhook_for_user_repo_with_installation_token(repo)
            db.session.delete(repo)


        # deleting user notifications
        logging.info(f"deleting user notifications for {user.github_login}")
        notifications = Notification.query.filter_by(user_id=user.id).all()
        for notification in notifications:
            db.session.delete(notification)

        # deleting user settings
        logging.info(f"deleting user settings for {user.github_login}")
        db.session.delete(user.settings)
        logging.info(f"deleting user github app for {user.github_login}")
        delete_user_github_app(user)


        # delete the user
        db.session.delete(user)
        db.session.commit()
        logging.info(f"deleted user profile for {user.github_login}")
        return True
    except SQLAlchemyError as e:
        logging.error(f"Failed to delete user profile for {user.github_login}: {e}")
        log_the_error_context(e)
        return False

    except Exception as e:
        logging.error(f"Failed to delete user profile for {user.github_login}: {e}")
        log_the_error_context(e)
        return False


def delete_user_github_app(user: User):
    logging.info(f"deleting github app for user {user.github_login}")
    if user.github_installation_id:
        validate_installation_access_token_for_user(user)
        jwt_token = generate_jwt()
        headers = {'Authorization': f'Bearer {jwt_token}',
                   'Accept': 'application/vnd.github.v3+json',
                   'X-GitHub-Api-Version': '2022-11-28'}
        response = requests.delete(f'https://api.github.com/app/installations/{user.github_installation_id}', headers=headers)
        if response.status_code == 204:
            logging.info(f"deleted github app for user {user.github_login}")
            return True
        else:
            logging.error(f"Failed to delete github app for user {user.github_login}: {response.content}")
            return False
    else:
        logging.info(f"user {user.github_login} does not have a github app installed")
        return True



def generate_jwt():
    logging.info("Generating JWT")
    logging.info(f"file: {config.get('GITHUB_APP_PRIVATE_KEY_FILE')}")
    with open(config.get("GITHUB_APP_PRIVATE_KEY_FILE"), 'rb') as pem_file:
        signing_key = jwk_from_pem(pem_file.read())
        logging.info(f"iat: int(time.time()): {int(time.time())}")
        logging.info(f"exp: int(time.time()) + 200: {int(time.time()) + 200}")
        current_time = int(time.time())-60
        payload = {
            # Issued at time
            'iat': current_time,
            # JWT expiration time (10 minutes maximum)
            'exp': current_time + 260,
            # GitHub App's identifier
            'iss': config.get("GITHUB_APP_ID")
        }
        logging.info(f"payload: {payload}, type(iat)={type(payload['iat'])}")
        jwt_instance = JWT()
        encoded_jwt = jwt_instance.encode(payload, signing_key, alg='RS256')
        logging.info("generated_encoded_jwt")
        return encoded_jwt

def get_installation_access_token_and_expiration_time(installation_id: str):
    logging.info(f"Getting installation access token for installation {installation_id}")
    jwt_token = generate_jwt()
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {jwt_token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    response = requests.post(url, headers=headers)

    if response.status_code != 201:
        raise Exception(f"Failed to get installation access token: {response.content}")
    logging.info(f"Installation access token response: {response.json()}")
    token = response.json()['token']
    logging.info(f"token: {token}")
    expires_at_datetime_aware = parse_to_utc_from_github_iso(response.json()['expires_at'].rstrip("Z"))
    logging.info(f"expires_at_datetime_aware: {expires_at_datetime_aware}")
    expires_at_timestamp = int(expires_at_datetime_aware.timestamp())-10
    logging.info(f"expires_at_timestamp: {expires_at_timestamp}")

    return token, expires_at_timestamp 


class InstallationIdNotFoundError(Exception):
    pass

class InstallationTokenValidationError(Exception):
    pass

def validate_installation_access_token_for_user(user: User):
    if not user.github_installation_id:
        raise InstallationIdNotFoundError(f"User {user.github_login} does not have a github_installation_id, cannot validate installation access token. probably github app not installed on their account")
    try:
        logging.info(f"Validating installation access token for user installation {user.github_installation_id}")
        if not user.github_installation_access_token_exists or user.github_installation_access_token_expires_at_timestamp < int(time.time()):
            logging.info(f"Installation access token has expired, refreshing")
            installation_access_token, expires_at_timestamp = get_installation_access_token_and_expiration_time(user.github_installation_id)
            user.github_installation_access_token_decrypted = installation_access_token
            user.github_installation_access_token_expires_at_timestamp = expires_at_timestamp
            user.github_installation_access_token_exists = True
        else:
            installation_access_token = user.github_installation_access_token_decrypted
        logging.info(f"Installation access token is valid")
        return installation_access_token
    except Exception as e:
        raise InstallationTokenValidationError(f"Failed to validate installation access token for user {user.github_login}: {e}") from e 

def refresh_user_access_token():
    logging.info(f"Refreshing user {current_user.github_login}'s access token")
    url = f"https://github.com/login/oauth/access_token?client_id={config.get('GITHUB_APP_CLIENT_ID')}&client_secret={config.get('GITHUB_APP_CLIENT_SECRET')}&refresh_token={current_user.github_refresh_token_decrypted}&grant_type=refresh_token"
    headers = {'Accept': 'application/json'}
    response = requests.post(url, headers=headers)
    if response.status_code != 200:
        raise UserAccessTokenRefreshError(f"Failed to refresh user {current_user.github_login}'s access token: {response.content}")

    access_token = response.json()['access_token']
    # transform seconds to datetimes
    current_user.github_user_access_token_decrypted = access_token
    current_user.github_user_access_token_expires_at_timestamp = int(time.time()) + int(response.json()['expires_in'])-5
    current_user.github_refresh_token_decrypted = response.json()['refresh_token']
    current_user.github_refresh_token_expires_at_timestamp = int(time.time()) + int(response.json()['refresh_token_expires_in'])-5
    db.session.commit()
    logging.info(f"Refreshed user {current_user.github_login}'s access token")
    return access_token


class UserAccessTokenRefreshError(Exception):
    pass

class UserAccessTokenValidationError(Exception):
    pass

def validate_user_access_token():
    if current_user.github_user_access_token_expires_at_timestamp:
        if current_user.github_user_access_token_expires_at_timestamp < int(time.time()):
            logging.info(f"User {current_user.github_login}'s access token has expired, refreshing")
            refresh_user_access_token()
        logging.info(f"User {current_user.github_login}'s access token is valid")
    else:
        raise UserAccessTokenValidationError(f"User {current_user.github_login} does not have a valid access token")


class WebhookDeactivationError(Exception): 
    pass


def track_repo_for_user(repo_name: str, repo_github_id: str, repo_private: bool):
    logging.info(f"starting track_repo_for_user")

    webhook_url = f'{config.get("APP_URL")}/webhook'
    validate_user_access_token()
    access_token = current_user.github_user_access_token_decrypted
    headers = {'Authorization': f'Bearer {access_token}',
               'Accept': 'application/vnd.github.v3+json',
               'X-GitHub-Api-Version': '2022-11-28'}
    logging.info(f"headers: {headers}")
    
    # Fetch the existing webhooks for the repository
    api_url = f'https://api.github.com/repos/{current_user.github_login}/{repo_name}/hooks'
    logging.info(f"api_url: {api_url}")
    response = requests.get(api_url, headers=headers)
    hook_id = None
    logging.info(f"response.status_code: {response.status_code}")
    if response.status_code == 404:
        hook_id = None 
    elif response.status_code == 200:
        existing_hooks = response.json()
        hook_id = next((hook['id'] for hook in existing_hooks if hook['config']['url'] == webhook_url), None)
    else:
        logging.error(f"Failed to retrieve webhooks for {repo_name}: {response.content}")
        return None

    # If the webhook does not exist, create a new one
    if not hook_id:
        data = {
            'name': 'web',
            'active': True,
            'events': ['push', 'pull_request'], # You can specify other events here
            'config': {
                'url': webhook_url,
                'content_type': 'json',
                'secret': config.get("GITHUB_REPOSITORY_WEBHOOK_SECRET"), # It's good to have a secret for security
            }
        }
        response = requests.post(api_url, json=data, headers=headers)
        if response.status_code == 403:
            logging.error(f"forbidden to set up webhook for {repo_name}: {response.content}")
            return None
        elif response.status_code == 404:
            logging.error(f"resource not found to set up webhook for {repo_name}: {response.content}")
            return None
        elif response.status_code == 422:
            logging.error(f"validation failed or spammed to set up webhook for {repo_name}: {response.content}")
            return None
        elif response.status_code == 201:
            logging.info(f"webhook created for {repo_name}: {response.content}")
        else:
            logging.error(f"Failed to set up webhook for {repo_name}: {response.content}")
            return None
        hook_id = response.json()['id']
    else:
        # activate the webhook if it exists and is inactive
        is_hook_active = False
        for hook in existing_hooks: # this is not None here
            if hook['id'] == hook_id:
                is_hook_active = hook['active']
                break
        if is_hook_active:
            logging.info(f"webhook for {repo_name} is already active")
        else:
            data = {
                'active': True,
            }
            response = requests.patch(f'https://api.github.com/repos/{current_user.github_login}/{repo_name}/hooks/{hook_id}', json=data, headers=headers)
            if response.status_code == 403:
                logging.error(f"forbidden to activate webhook for {repo_name}: {response.content}")
                return None
            elif response.status_code == 404:
                logging.error(f"resource not found to activate webhook for {repo_name}: {response.content}")
                return None
            elif response.status_code == 422:
                logging.error(f"validation failed or spammed to activate webhook for {repo_name}: {response.content}")
                return None
            elif response.status_code == 200:
                logging.info(f"webhook activated for {repo_name}: {response.content}")
            else:
                logging.error(f"Failed to activate webhook for {repo_name}: {response.content}")
                return None

    # Check if repo exists
    repo = Repo.query.filter_by(github_id=repo_github_id).first()
    # Create a new repo if it doesn't exist
    
    if not repo:
        repo = Repo(name=repo_name, owner_github_id=current_user.github_id, \
                owner_github_login=current_user.github_login, github_id=repo_github_id, \
                webhook_id=hook_id, webhook_active=True, added_timestamp=time.time(),
                    private=repo_private)
        db.session.add(repo)
    else:
        repo.added_timestamp = time.time()
        repo.deleted = False
        repo.private = repo_private
        # if the repo exists, update the webhook id
        repo.webhook_id = hook_id
        repo.webhook_active = True
    db.session.commit()

    return hook_id


def deactivate_webhook_for_user_repo_with_installation_token(repo: Repo):
    logging.info(f"starting deactivate_webhook_for_user_repo_with_installation_token")
    user = User.query.filter_by(github_id=repo.owner_github_id).first()
    if not user:
        raise Exception(f"User with github_id {repo.owner_github_id} does not exist so cannot deactivate the webhook")
    logging.info(f"user: {user.name} with repo_name: {repo.name}")
    if not user.github_installation_id:
        raise Exception(f"User {user.github_login} does not have a github_installation_id, so cannot deactivate the webhook. probably github app not installed on their account")

    installation_access_token = validate_installation_access_token_for_user(user)
    headers = {'Authorization': f'Bearer {installation_access_token}',
               'Accept': 'application/vnd.github.v3+json',
               'X-GitHub-Api-Version': '2022-11-28'}

    response = requests.patch(f'https://api.github.com/repos/{user.github_login}/{repo.name}/hooks/{repo.webhook_id}', json={'active': False}, headers=headers)
    
    
    if response.status_code == 200:
        logging.info("Webhook deactivated successfully")
        repo.webhook_active = False
        db.session.commit()
        return True
    elif response.status_code == 404:  # Not Found
        logging.error(f"Webhook not found for {repo.name}:404 :{response.content}")
        repo.webhook_active = False
        repo.webhook_id = None
        db.session.commit()
        return False
    elif response.status_code == 401: 
        logging.info(f"Unauthorized to activate webhook for {repo.name}:{response.status_code}: {response.content}")
        repo.webhook_id = None
        repo.webhook_active = False
        db.session.commit()
        return False 
    else:
        logging.error(f"Failed to deactivate webhook for {repo.name}:{response.status_code}: {response.content}")
        raise WebhookDeactivationError(f"Failed to deactivate webhook for {repo.name}:{response.status_code}: {response.content}")

def reactivate_webhook_for_user_repo_with_installation_token(repo: Repo):
    """
    Reactivates the webhook for the repo that's in user ownership.
    Does db.session.commit() at the end.
    If error -> resets the webhook_active to False and webhook_id to None.

    returns True if successful, False if not
    """
    logging.info(f"starting reactivate_webhook_for_user_repo_with_installation_token")
    user = User.query.filter_by(github_id=repo.owner_github_id).first()
    if not user:
        raise Exception(f"User with github_id {repo.owner_github_id} does not exist so cannot reactivate the webhook")
    logging.info(f"user: {user.name} with repo_name: {repo.name}")
    if not user.github_installation_id:
        logging.info(f"User {user.github_login} does not have a github_installation_id, so cannot reactivate the webhook. probably github app not installed on their account")
        repo.webhook_active = False

    installation_access_token = validate_installation_access_token_for_user(user)
    headers = {'Authorization': f'Bearer {installation_access_token}',
               'Accept': 'application/vnd.github.v3+json',
               'X-GitHub-Api-Version': '2022-11-28'}

    response = requests.patch(f'https://api.github.com/repos/{user.github_login}/{repo.name}/hooks/{repo.webhook_id}', json={'active': True}, headers=headers)
    
    
    if response.status_code == 200:
        logging.info("Webhook activated successfully")
        repo.webhook_active = True
        repo.added_timestamp = time.time()
        db.session.commit()
    elif response.status_code == 404:  # Not Found
        logging.error(f"Webhook not found for {repo.name}:404 :{response.content}")
        repo.webhook_active = False
        repo.webhook_id = None
    elif response.status_code == 401: 
        logging.info(f"Unauthorized to activate webhook for {repo.name}:{response.status_code}: {response.content}")
        repo.webhook_id = None
        repo.webhook_active = False
    else:
        logging.error(f"Failed to activate webhook for {repo.name}:{response.status_code}: {response.content}")
        raise WebhookReactivationError(f"Failed to activate webhook for {repo.name}:{response.status_code}: {response.content}")
    db.session.commit()
    return repo.webhook_active

class WebhookReactivationError(Exception):
    pass


def untrack_repo_for_user(user: User, repo_name: str):

    repo = Repo.query.filter_by(name=repo_name, owner_github_login=user.github_login).first()
    if not repo:
        print("Repository not found in untrack_repo_for_user")
        return False

    hook_id = repo.webhook_id
    validate_user_access_token()
    headers = {'Authorization': f'token {user.github_user_access_token_decrypted}'}
    response = requests.delete(f'https://api.github.com/repos/{user.github_login}/{repo_name}/hooks/{hook_id}', headers=headers)
    
    print(f"Response Status Code: {response.status_code}")
    print(f"Response Content: {response.content}")
    
    if response.status_code == 204:
        logging.info("Webhook deleted successfully")
    elif response.status_code == 404:  # Not Found
        logging.info("Webhook not found 404")
    else:
        logging.error("Failed to delete webhook status: {response.status_code}")
        return False

    repo.deleted = True
    repo.webhook_id = None
    repo.webhook_active = False
    db.session.commit()
    return True


def fetch_commit_data(github, repo: Repo, commit_sha: str):
    last_exception = None
    for i in range(MAX_RETRIES):
        try:
            url = f"https://api.github.com/repos/{repo.owner_github_login}/{repo.name}/commits/{commit_sha}"
            response = github.get(url)
            response.raise_for_status()
            response_data = response.json()
            return response_data, url
        except (RequestException, ValueError) as e:
            logging.error(f"Failed to fetch commit {commit_sha} on attempt {i+1}: {e}")
            last_exception = e
            time.sleep(RETRY_DELAY)

    raise FetchCommitDataError(f"Failed to fetch commit {commit_sha} after {MAX_RETRIES} attempts") from last_exception


def get_or_create_unfinished_post_for_user(repo: Repo, user: User, branch: Branch):
    logging.info("enter get_or_create_unfinished_post_for_user")
    post = Post.query.filter_by(repo_id=repo.id, user_id=user.id, not_finished=True).first()
    if not post:
        logging.info(f"creating a new post with author_github_login as: {user.github_login}")
        post = Post(user=user, repo=repo, author_github_login=user.github_login,
                    author_github_id=user.github_id, branch=branch)
        db.session.add(post)
        # this is used when getting earlier missed commits and we want to know the latest commit we should start the search from
        repo.added_timestamp = time.time() 
    logging.info("leave get_or_create_unfinished_post_for_user")
    return post


def create_post_data(github_ses, post: Post):
    logging.info("enter create_post_data")
    if post.author_github_login:
        post_data = f"Author: {post.author_github_login}\n"
    else:
        post_data = "Author: Unknown\n"
    changes_across_all_files = 0
    sorted(post.commits, key=lambda x: x.creation_timestamp)
    for commit in post.commits:
        logging.info(f"commit: {commit}")
        commitdata, url = fetch_commit_data(github_ses, post.repo, commit.sha)

        commit.message = commitdata['commit']['message']
        logging.info(f"commit.message: {commit.message}")
        post_data += f"Commit Message: {commit.message}:\n"
        date_str = commitdata['commit']['committer']['date']
        logging.info(f"date_str: {date_str}")
        commit.creation_timestamp = int(parse_to_utc_from_github_iso(date_str.rstrip("Z")).timestamp())
        logging.info(f"commit.creation_timestamp: {commit.creation_timestamp}")
        post_data += " Files:\n"
        for file in commitdata['files']:
            # Check if 'patch' exists in the file dictionary
            if 'patch' in file:
                if file['changes'] is None:
                    file['changes'] = 0
                changes_across_all_files += int(file['changes'])
                lines_in_patch = len(file['patch'].split("\n"))
                if lines_in_patch > 150:
                    # cut the patch to 150 lines
                    file['patch'] = "\n".join(file['patch'].split("\n")[:150])

                filename = file['filename']
                logging.info(f"filename: {filename}")
                # we have to filter out the files that are cache or binary or not code files written by human
                #analysis_method = get_file_analysis_method(filename, file['patch'], post.repo)
                analysis_method = "full"
                logging.info(f"analysis_method: {analysis_method}")
                if analysis_method == "full":
                    logging.info("full")
                    post_data += f"  in file {file['filename']}:\n"
                    post_data += f"  {file['patch']}\n"
                elif analysis_method == "never":
                    logging.info("never")
                    post_data += f"  file: {file['filename']} was added\n"
                elif analysis_method == "beginning":
                    logging.info("beginning of the file")
                    first_ten_lines = file['patch'].split("\n")[:10]
                    post_data += f"  in file {filename}:\n"
                    post_data += f"  {first_ten_lines}\n"

    if post.lines_changed is None:
        post.lines_changed = 0
    logging.info(f"post.lines_changed before: {post.lines_changed}")
    post.lines_changed = int(post.lines_changed) + int(changes_across_all_files)
    logging.info(f"post.lines_changed after: {post.lines_changed}")
    logging.info("leave create_post_data")
    return post_data

def analyze_post(post: Post, post_data: str, provider: str, model: str):
    logging.info("enter analyze_post")
    if provider == "openai":
        logging.info("provider is openai")
        post_content, programming_language_used = gpt_generate_summary_for_user_commits_openai(post_data, model)
        #if post.summary_token_count is None:
        #    post.summary_token_count = 0
        #post.summary_token_count += int(tokens)
        post.programming_language = programming_language_used
        post.summary_provider = "openai"
        post.summary_model = model
        logging.info("leave analyze_post")
        return post_content
    elif provider == "groq":
        logging.info("provider is groq")
        post_content, programming_language_used = gpt_generate_summary_for_user_commits_groq(post_data, model)
        #if post.summary_token_count is None:
        #    post.summary_token_count = 0
        #post.summary_token_count += int(tokens)
        post.programming_language = programming_language_used
        post.summary_provider = "groq"
        post.summary_model = model
        logging.info("leave analyze_post")
        return post_content
    elif provider == "local":
        logging.info("provider is local")
        post_content, programming_language_used = gpt_generate_summary_for_user_commits_local(post.repo.repo_description, post_data, model)
        post.programming_language = programming_language_used
        post.summary_provider = 'local'
        post.summary_model = model
        logging.info("leave analyze_post")
        return post_content
    logging.info("provider is not openai or groq, returning None")
    return None

def post_post(post_data: str, post: Post, provider: str, model: str):
    post_content = analyze_post(post, post_data, provider, model)

    post.not_finished = False
    # encrypting automatically if repo is private
    post.content_decrypted = post_content
    post.creation_timestamp = max([c.creation_timestamp for c in post.commits])
    return post_content


def judge_significance(post_data: str, post: Post, provider: str, model: str):
    if provider == "openai":
        logging.info("provider is openai")
        decision = gpt_judge_with_openai(post_data, model)
        if post.judging_token_count is None:
            post.judging_token_count = 0
        
        post.judging_token_count += count_tokens_improved(post_data)
        return decision

    elif provider == "groq":
        logging.info("provider is groq")
        decision = gpt_judge_with_groq(post_data, model)
        if post.judging_token_count is None:
            post.judging_token_count = 0
        post.judging_token_count += count_tokens_improved(post_data)
        return decision
    elif provider == 'local':
        logging.info("provider is local")
        if post.judging_token_count is None:
            post.judging_token_count = 0
        post.judging_token_count += count_tokens_improved(post_data)
        return gpt_judge_with_local(post_data, model)
    elif provider == "anthropic":
        logging.info("provider is anthropic")
        if post.judging_token_count is None:
            post.judging_token_count = 0
        post.judging_token_count += count_tokens_improved(post_data)
        return gpt_judge_with_anthropic(post_data, model)
        
    return None

class ParentCommitNotFoundError(Exception):
    pass

def handle_new_commit(repo: Repo, commit_sha: str, cdata: dict, current_branch: Branch, github: requests.Session):
    with db.session.no_autoflush:
        logging.info(f"current_commit is None, creating a new commit")

        commit_timestamp = int(parse_to_utc_from_github_iso(cdata['commit']['committer']['date'].rstrip("Z")).timestamp())
        logging.info(f"commit_timestamp: {commit_timestamp}")
        if commit_timestamp < repo.added_timestamp:
            logging.info("commit went under the repos added_timestamp, won't process this commit")
            return
        author = author_github_id = author_github_login = None
        if 'author' in cdata and cdata['author'] is not None:
            logging.info(f"author in data found: {cdata['author']}")
            author_github_id = cdata['author']['id']
            author_github_login = cdata['author']['login']
            author = User.query.filter_by(github_id=author_github_id).first()
        if not author:
            raise UserNotFoundError(f"author is None when creating new commit, this should not happen")

        current_commit = Commit(sha=commit_sha, branch=current_branch, repo=repo,
                author_github_id=author_github_id,author_github_login=author_github_login,
                creation_timestamp=commit_timestamp,link=f"https://github.com/{repo.owner_github_login}/{repo.name}/commit/{commit_sha}")

        author = User.query.filter_by(github_id=author_github_id).first()
        current_commit.user = author

        db.session.add(current_commit)

        logging.info(f"starting to go through parents")
        for parent in cdata['parents']:
            parent_sha = parent['sha']
            logging.info(f"parent_sha: {parent_sha}")
            parent_commit = Commit.query.filter_by(sha=parent_sha).first()
            if parent_commit is None:
                # we can fix it here by recursively calling this same function with the before_sha
                logging.warning(f"parent_commit is None with sha:{parent_sha}, we try fixing it here")

                parentdata,url = fetch_commit_data(github, repo, parent_sha)
                parent_timestamp = int(parse_to_utc_from_github_iso(parentdata['commit']['committer']['date'].rstrip("Z")).timestamp())
                if parent_timestamp < repo.added_timestamp:
                    logging.info("went under repos added_timestamp, leaving parent as none")
                    continue

                handle_new_commit(repo, parent_sha, parentdata, current_branch, github)
                # lets check again
                parent_commit = Commit.query.filter_by(sha=parent_sha).first()
                if parent_commit is None:
                    raise ParentCommitNotFoundError(f"parent_commit is still None with sha:{parent_sha}, we couldn't fix it with recursion")
                logging.info(f"parent_commit is now {parent_sha}")
            current_commit.parents.append(parent_commit)
            logging.info(f"found and linked parent {parent_sha} to commit {commit_sha}")


        logging.info(f"repo is user repo, getting or creating an unfinished post for user")
        post = get_or_create_unfinished_post_for_user(repo, author, current_commit.branch)
        current_commit.post = post
        post_data = create_post_data(github,post)
        logging.info(f"post_data:{post_data}")

        provider = 'groq'
        model = ""
        if provider == 'local':
            model = config.get('DEFAULT_LLAMA_MODEL')
        elif provider == 'openai':
            model = config.get('NEWEST_OPENAI_MODEL')
        elif provider == 'groq':
            model = config.get('NEWEST_LLAMA_MODEL')

        sig = judge_significance(post_data, post, provider, model)
        logging.info(f"sig : {sig}")
        if sig == "significant" or (post.user.github_login == "rasmustestaccount" and post.repo.name == "alwayssignificant"):
            logging.info("significant")
            post_content = post_post(post_data, post, provider, model)
            logging.info("post created")
            if author.post_to_x_active:
                post_to_x(author, post)
        else:
            logging.info("Not significant, waiting for more commits to judge")
    db.session.commit()


def handle_existing_commit(repo: Repo, current_branch: Branch, current_commit: Commit):
    with db.session.no_autoflush:

        logging.info(f"current_commit is not None, must be a merge or push that corrects some before misbranched commits")

        logging.info(f"repo.main_branch_name: {repo.main_branch_name}")
        logging.info(f"repo.hotfix_branch_contains_name: {repo.hotfix_branch_contains_name}")
        logging.info(f"repo.dev_branch_name: {repo.dev_branch_name}")
        logging.info(f"current_commit.branch.name: {current_commit.branch.name}")
        logging.info(f"repo.main_branch_in_use: {repo.main_branch_in_use}")
        logging.info(f"repo.dev_branch_in_use: {repo.dev_branch_in_use}")
        logging.info(f"repo.hotfix_branch_in_use: {repo.hotfix_branch_in_use}")
        if repo.main_branch_in_use and current_commit.branch.name == repo.main_branch_name:
            logging.info("current_commit's branch is main branch, we won't rebranch it")
        elif repo.dev_branch_in_use and current_commit.branch.name == repo.dev_branch_name:
            logging.info("current_commit's branch is dev branch, we won't rebranch it")
        elif repo.hotfix_branch_in_use and repo.hotfix_branch_contains_name.lower() in current_commit.branch.name.lower():
            logging.info("current_commit's branch is hotfix branch, we won't rebranch it")
        elif (repo.main_branch_in_use and current_branch.name == repo.main_branch_name) \
                or (repo.dev_branch_in_use and current_branch.name == repo.dev_branch_name) \
                or (repo.hotfix_branch_in_use and repo.hotfix_branch_contains_name.lower() in current_branch.name.lower()):
            logging.info("current_branch is main, dev or hotfix branch, we won't rebranch any of the commits hanging on it")
        else:
            logging.info("we will rebranch it")
            previous_branch_name = current_commit.branch.name
            logging.info(f"previous_branch_name: {previous_branch_name}")
            current_commit.branch = current_branch
            logging.info(f"current_commit.branch.name: {current_commit.branch.name}")
            current_commit.previous_branch_name = previous_branch_name
            logging.info(f"current_commit.previous_branch_name: {current_commit.previous_branch_name}")
    db.session.commit()

def handle_commit(repo: Repo, commit_sha: str, current_branch: Branch, github: requests.Session):
    """
    All the errors will go to handle_commits function which calls this exclusively.
    I have tried to make errors specific to different functions.
    handle_new_commit can be recursive if the parent_commit that should be found is not found in the db.
    """
    logging.info(f"---------------------------------------------- entering handle_commit with commit_sha: {commit_sha}")

    with db.session.no_autoflush:
        cdata,url = fetch_commit_data(github, repo, commit_sha)
        logging.info(f"cdata: {cdata}")
        current_commit = Commit.query.filter_by(sha=commit_sha).first()
        if current_commit is None:
            handle_new_commit(repo, commit_sha, cdata, current_branch, github)
        else:
            handle_existing_commit(repo, current_branch, current_commit)
            
        logging.info(f"FINALLY COMMITING THE CHANGES TO DB")
    db.session.commit()
    logging.info(f"leaving handle_commit with commit_sha: {commit_sha}")



class UserNotFoundError(Exception):
    pass


class UnauthorizedError(Exception):
    pass

def handle_commits(repo: Repo, commit_shas: list[str], branch_name: str):
    """
    Handles a list of commit SHAs for a repository and makes posts.
    Args:
        repo: The repository.
        commits_data: A list of commit data dictionaries.
        branch_name: The name of the branch that the commits are in.
    """
    github = None
    current_branch = None
    try:
        with db.session.no_autoflush:
            github = requests.Session()
            user = User.query.filter_by(github_id=repo.owner_github_id).first()
            if not user:
                raise UserNotFoundError(f"User with github_login {repo.owner_github_login} not found for the incoming commit payload")

            installation_access_token = validate_installation_access_token_for_user(user) 
            github.headers.update({'Authorization': f'Bearer {installation_access_token}',
                                   'Accept': 'application/vnd.github.v3+json',
                                   'X-GitHub-Api-Version': '2022-11-28'})
            
            current_branch = Branch.query.filter_by(name=branch_name, repo=repo).first()
            logging.info(f"current_branch: {current_branch}")
            if not current_branch:
                current_branch = Branch(name=branch_name, repo=repo)
                db.session.add(current_branch)
                logging.info(f"created a new branch {branch_name}")
    except UserNotFoundError as e:
        logging.error(f"UserNotFoundError occurred while handling commits: {e}")
        db.session.rollback()
        log_the_error_context(e,100, "UserNotFoundError occurred while handling commits which probably means the user has deleted their account but some webhook is still active and they must have the installation still on their account")
        return
    except UnauthorizedError as e:
        logging.error(f"UnauthorizedError occurred while handling commits: {e}")
        db.session.rollback()
        log_the_error_context(e,100, "UnauthorizedError occurred while handling commits which probably means the user has lost their premium subscription but some webhook is still active and they must have the installation still on their account")
        return
    except InstallationTokenValidationError as e:
        logging.error(f"InstallationTokenValidationError occurred while reciving payload: {e}")
        db.session.rollback()
        log_the_error_context(e,200, "InstallationTokenValidationError occurred while creating github ses in payload reciving")
        return
    except InstallationIdNotFoundError as e:
        logging.error(f"InstallationIdNotFoundError occurred while creating github ses for payload: {e}")
        db.session.rollback()
        log_the_error_context(e,200, "InstallationIdNotFoundError occurred while creating github ses for payload")
        return
    except Exception as e:
        logging.error(f"Failed to create github session or branch: {e}")
        db.session.rollback()
        log_the_error_context(e,300, "error occurred while creating github session or branch")
        return

    # NOW:
    # current_branch is either a new branch or an existing branch
    # commit_shas is a list of commit shas
    # repo is the repo object
    try:
        for commit_sha in commit_shas:
            try:
                logging.info(f"---------------------------------------------- entering handle_commits with commit_sha: {commit_sha}")
                handle_commit(repo, commit_sha, current_branch, github)

            except GPTCreateSummaryError as e:
                db.session.rollback()
                logging.error(f"GPTCreateSummaryError occurred while handling commit: {commit_sha} on repo: {repo.name}: {e}")
                create_user_notification(user, f"Error occurred while creating a post for commit {commit_sha} on repo {repo.name}: {e}")
                log_the_error_context(e, 500,f"gptcreatesummaryerror occurred while handling commit: {commit_sha} on repo: {repo.name}")
            except SQLAlchemyError as e:
                db.session.rollback()
                logging.error(f"SqlAlchemyError occurred while handling commit: {commit_sha} on repo: {repo.name}: {e}")
                log_the_error_context(e, 1000,f"sqlalchemyerror occurred while handling commit: {commit_sha} on repo: {repo.name}")
            except UserNotFoundError as e:
                db.session.rollback()
                logging.error(f"UserNotFoundError occurred while handling commit: {commit_sha} on repo: {repo.name}: {e}")
                log_the_error_context(e, 500,f"usernotfounderror occurred while handling commit: {commit_sha} on repo: {repo.name}")
            except ParentCommitNotFoundError as e:
                db.session.rollback()
                logging.error(f"ParentCommitNotFoundError occurred while handling commit: {commit_sha} on repo: {repo.name}: {e}")
                log_the_error_context(e, 1000,f"parentcommitnotfounderror occurred while handling commit: {commit_sha} on repo: {repo.name}")
            except FetchCommitDataError as e:
                db.session.rollback()
                logging.error(f"Error occurred on fetchcommitdata while handling commit: {commit_sha} on repo: {repo.name}: {e}")
                log_the_error_context(e, 500,f"fetchcommitdataerror occurred while handling commit: {commit_sha} on repo: {repo.name}")
            except ValueError as e:
                db.session.rollback()
                logging.error(f"ValueError occurred while handling commit: {commit_sha} on repo: {repo.name}: {e}")
                log_the_error_context(e, 500,f"valueerror occurred while handling commit: {commit_sha} on repo: {repo.name}")
            except Exception as e:
                db.session.rollback()
                logging.error(f"Error occurred while handling commit: {commit_sha} on repo: {repo.name}: {e}")
                log_the_error_context(e, 1000,f"error occurred while handling commit: {commit_sha} on repo: {repo.name}")


        logging.info(f"analyzed commits for {repo.name} on branch {current_branch.name}")
        # update the latest commit sha of the branch
        logging.info(f"commit_shas[-1]: {commit_shas[-1]}")
        current_branch.latest_commit_sha = commit_shas[-1]
        logging.info(f"current_branch.latest_commit_sha: {current_branch.latest_commit_sha}")
        repo.last_push_timestamp = int(time.time())
        db.session.commit()
        logging.info(f"repo.last_push_timestamp: {repo.last_push_timestamp}")
        logging.info(f"committed the changes to db for branch {current_branch.name}")
        return True
    except Exception as e:
        logging.error(f"Error occurred while handling commits: {e}")
        db.session.rollback()
        log_the_error_context(e, 1000, "error occurred while handling commits, this is the last error clause on handle_commits")

def count_tokens_improved(text):
    # Handle strings as single tokens
    text = re.sub(r'".*?"', '"STRING"', text)
    text = re.sub(r"'.*?'", "'STRING'", text)

    # Handle comments as single tokens
    text = re.sub(r'//.*?\n', ' //COMMENT\n', text)
    text = re.sub(r'/\*.*?\*/', ' /*COMMENT*/ ', text, flags=re.DOTALL)

    # Tokenize by splitting on whitespace and counting punctuations as separate tokens
    tokens = text.split()

    # Count newlines as separate tokens
    newline_count = text.count('\n')

    # Count spaces as separate tokens
    space_count = text.count(' ')

    # Count each punctuation as a separate token, but exclude the ones in 'STRING' or 'COMMENT'
    punctuation_count = sum(1 for char in re.sub(r'"STRING"|\'STRING\'|//COMMENT|/\*COMMENT\*/', '', text) if char in string.punctuation)

    return len(tokens) + newline_count + space_count + punctuation_count
   
def count_tokens(text):
    return len(text.split()) + text.count('\n') + text.count(' ') + sum(1 for char in text if char in string.punctuation)

class RepoNotFoundError(Exception):
    pass

class RepoDeletedError(Exception):
    pass


def handle_payload(payload: dict):
    """
    Handles a webhook payload for commits from GitHub.
    """
    try:
        repo_name = payload['repository']['name']
        repo_github_id = payload['repository']['id']
        repo_owner_github_id = payload['repository']['owner']['id']
        repo_owner_github_login = payload['repository']['owner']['login']
        repo_owner_type = payload['repository']['owner']['type']

        repo = Repo.query.filter_by(github_id=repo_github_id).first()
        if not repo:
            raise RepoNotFoundError(f"Repo with github_id {repo_github_id} not found")

        if repo_owner_type != "User":
            raise Exception(f"repo_owner_type {repo_owner_type} is not supported")

        if repo.deleted:
            user = User.query.filter_by(github_id=repo.owner_github_id).first()
            deactivate_webhook_for_user_repo_with_installation_token(repo)
            raise RepoDeletedError(f"Repo with github_id {repo_github_id} is deleted")

        if not repo.webhook_active:
            user = User.query.filter_by(github_id=repo.owner_github_id).first()
            if user:
                reactivate_webhook_for_user_repo_with_installation_token(repo)
            else:
                deactivate_webhook_for_user_repo_with_installation_token(repo)


        commit_shas = []
        for commit in payload['commits']:
            commit_shas.append(commit['id'])
        branch_name = payload['ref'].split('/')[-1]

        logging.info(f"Received push payload for {repo_owner_github_login}/{repo_name} with {len(commit_shas)} commit(s) in branch {branch_name}")

        user = User.query.filter_by(github_id=repo.owner_github_id).first()
        if user.suspended:
            logging.info(f"User {user.github_login} is suspended, not processing the commits")
            deactivate_webhook_for_user_repo_with_installation_token(repo)
            create_admin_notification(f"User {user.github_login} is suspended, not processing the commits")
            return False

        # TODO
        # currently collaborators are not supported, but they can be in the future:
        # /repos/{owner}/{repo}/collaborators endpoint gets us the collaborators and 
        # we can allow user to also track repos they are collaborators of
        # and just put the author of the commit as the user who is the collaborator
        # and then when checking unsignificant commits, we must filter commits for that user only
        if repo.owner_github_login != user.github_login:
            logging.info(f"probably some other collaborator is pushing to the repo, not processing the commits")
            repo.added_timestamp = int(time.time()) # to reset the parent finding
            db.session.commit()
            return False

        daily_post_count = Post.query.filter(Post.creation_timestamp > int(time.time())-86400, Post.user_id==user.id ).count()
        logging.info(f"User {user.github_login} has posted {daily_post_count} posts today")
        if daily_post_count >= 5:
            logging.info(f"User {user.github_login} has reached the daily post limit of 5, not processing the commits")
            create_admin_notification(f"User {user.github_login} has reached the daily post limit of 5, not processing the commits")
            repo.added_timestamp = int(time.time()) # to reset the parent finding
            db.session.commit()
            return False
        

        success = handle_commits(repo, commit_shas, branch_name)
        #log_the_push_context("Received push payload for {repo_owner_github_login}/{repo_name} with {len(commit_shas)} commit(s) in branch {branch_name}")
        logging.info(f"Handled push payload for {repo_owner_github_login}/{repo_name} with {len(commit_shas)} commit(s) in branch {branch_name}")
        return success
    except KeyError as ke:
        logging.error(f"Missing required field: {ke}")
        db.session.rollback()
        log_the_error_context(ke,800, "missing required field")
    except RepoNotFoundError as e:
        logging.error(f"Repo not found for incoming commits: {e}")
        db.session.rollback()
        log_the_error_context(e,100, "repo not found for incoming commits, how did this happen?")
    except RepoDeletedError as e:
        logging.error(f"Repo deleted: {e}")
        db.session.rollback()
        log_the_error_context(e,100, "repo deleted for incoming commits, how did this happen?")
    except WebhookDeactivationError as e:
        logging.error(f"Webhook deactivation error: {e}")
        db.session.rollback()
        log_the_error_context(e,100, "webhook deactivation error")
    except WebhookReactivationError as e:
        logging.error(f"Webhook reactivation error: {e}")
        db.session.rollback()
        log_the_error_context(e,100, "webhook reactivation error")

    except Exception as e:
        logging.error(f"Error occurred while handling payload: {e}")
        db.session.rollback()
        log_the_error_context(e,1000, "error occurred while handling payload")
    

