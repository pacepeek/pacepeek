from os import access
import base64,time,logging,re,requests
from datetime import timedelta
from requests_oauthlib import OAuth2Session
from . import config,db
from datetime import datetime
from .models import User, Post, Notification, Repo
from .utils import create_user_notification


def make_x_token():
    return OAuth2Session(config.get("X_CLIENT_ID"), redirect_uri=config.get("X_REDIRECT_URL"), scope=config.get("X_SCOPES"))

def prevent_twitter_links(text):
    def replace_filename(match):
        filename = match.group(0)
        return filename.replace(".", ".\u200B")
    logging.info(f"Preventing twitter links in {text}")

    ret = re.sub(r'\w+\.\w+', replace_filename, text)
    logging.info(f"Prevented twitter links in {ret}")
    return ret

def post_daily_summary_to_x(repo: Repo, summary: str):
    logging.info("Posting to X!")
    
    post_content = prevent_twitter_links(summary)
    payload = {"text": f"{post_content}"}
    response = None
    logging.info("Validating access token")
    logging.info("Access token validated")

    access_token = repo.x_access_token_decrypted
    
    response = requests.request(
        "POST",
        "https://api.x.com/2/tweets",
        json=payload,
        headers={
            "Authorization": "Bearer {}".format(access_token),
            "Content-Type": "application/json",
        },
    )
    logging.info(response.json())
    response.raise_for_status()  # Will raise an HTTPError for bad responses

    return response

def truncate_post_content(user_name, repo_name, content, max_length=280):
    prefix = f"repo {repo_name}:\n"
    remaining_chars = max_length - len(prefix)
    if len(content) > remaining_chars:
        return prefix + content[:remaining_chars-3] + "..."
    return prefix + content


def make_post_request(access_token: str, payload: dict) -> requests.Response:
    """
    Make a POST request to X API with the given payload and access token.
    Returns the response object.
    """
    response = requests.request(
        "POST",
        "https://api.x.com/2/tweets",
        json=payload,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
    )
    
    logging.info(f"Response status code: {response.status_code}")
    logging.info(f"Response headers: {response.headers}")
    logging.info(f"Raw response content: {response.content}")
    logging.info(f"Response data from X: {response.json()}")
    
    response.raise_for_status()
    return response

def post_to_x(user: User, post: Post):
    logging.info("Posting to X!")

    if not user.is_premium:
        logging.info("User is not premium, not posting")
        return


    try:
        validate_access_token_from_x(user)
        logging.info("X user access token validated successfully")

        # Make initial post
        post_content = prevent_twitter_links(post.content)
        initial_payload = {
            "text": truncate_post_content(post.user.name, post.repo.name, post_content)
        }

        initial_response = make_post_request(user.x_access_token_decrypted, initial_payload)
        initial_tweet_data = initial_response.json()
        tweet_id = initial_tweet_data['data']['id']

        # Make reply with link
        logging.info("POST.ID: ", post.id)
        reply_payload = {
            "reply": {"in_reply_to_tweet_id": tweet_id},
            "text": f"Read the full post here: https://pacepeek.com/p/{post.id}"
        }
        reply_response = make_post_request(user.x_access_token_decrypted, reply_payload)

        post.status = 'success'
        create_user_notification(
            user, 
            "Your post was successfully posted to X!", 
            f"https://x.com/{user.x_username}/status/{tweet_id}"
        )
        db.session.commit()
        return initial_response

    except Exception as e:
        logging.error(f"An error occurred while posting the tweet: {e}")
        post.status = 'failed'
        post.error_message = str(e)
        db.session.commit()


def validate_access_token_from_x(user: User):
    if time.time() >= user.x_access_token_expires_at_timestamp:
        refresh_access_token_from_x(user)
        

def refresh_access_token_from_x(user: User):
    url = "https://api.x.com/2/oauth2/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'refresh_token': user.x_refresh_token_decrypted,
        'grant_type': 'refresh_token',
    }
    basic_auth_str = f"{config.get('X_CLIENT_ID')}:{config.get('X_CLIENT_SECRET')}"
    basic_auth_encoded = base64.b64encode(basic_auth_str.encode('utf-8')).decode('utf-8')
    headers['Authorization'] = f"Basic {basic_auth_encoded}"
    
    
    response = None
    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()  # Will raise an HTTPError for bad responses
        
        new_tokens = response.json()
        user.x_access_token_decrypted = new_tokens['access_token']
        user.x_access_token_exists = True
        user.x_refresh_token_decrypted = new_tokens['refresh_token']
        user.x_access_token_expires_at_timestamp = time.time() + new_tokens['expires_in']
        user.post_to_x_active = True
        db.session.commit()

    except requests.RequestException as e:
        logging.error(f"An error occurred while refreshing the token: {e}")
        logging.error(f"Response content: {response.content if response else 'No response'}")  # Debugging line
        raise Exception(f"Failed to refresh token: {response.content if response else e}")
   

def revoke_access_token_from_x(user: User):

    print("Revoking token")
    response = None
    try:
        url = "https://api.x.com/2/oauth2/revoke"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        basic_auth_str = f"{config.get('X_CLIENT_ID')}:{config.get('X_CLIENT_SECRET')}"
        basic_auth_encoded = base64.b64encode(basic_auth_str.encode('utf-8')).decode('utf-8')
        headers['Authorization'] = f"Basic {basic_auth_encoded}"
        validate_access_token_from_x(user)

        data = {
            'token': user.x_access_token_decrypted,
            'token_type_hint': 'access_token'
        }
         
        response = requests.post(url, headers=headers, data=data)
        print(response.json())
        response.raise_for_status()  # Will raise an HTTPError for bad responses
        # Invalidate the token in your database
        user.x_access_token_encrypted = None
        user.x_refresh_token_encrypted = None
        user.x_access_token_exists = False
        user.x_token_expires_at = None
        user.x_username = None
        user.post_to_x_active = False
        db.session.commit()
    except requests.RequestException as e:
        logging.error(f"An error occurred while revoking the token: {e}")
        logging.error(f"Response content: {response.content if response else 'No response'}")  # Debugging line
        user.x_access_token_encrypted = None
        user.x_refresh_token_encrypted = None
        user.x_access_token_exists = False
        user.x_token_expires_at = None
        user.x_username = None
        db.session.commit()
   
