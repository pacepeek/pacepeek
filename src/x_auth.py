import base64,os,re,hashlib,requests,logging
from requests_oauthlib import OAuth2Session
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, session, url_for, flash, jsonify
import pprint,time
from flask_login import current_user, login_required
from .x_utils import make_x_token, post_to_x, refresh_access_token_from_x, revoke_access_token_from_x
from . import config, db
from .utils import get_latest_post
from .models import Repo

auth_url = "https://twitter.com/i/oauth2/authorize"
token_url = "https://api.twitter.com/2/oauth2/token"


x_auth = Blueprint('x_auth', __name__)



@login_required
@x_auth.route("/x_auth")
def x_auth_user():
    x_token = make_x_token()

    # Create a code verifier
    code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
    session['code_verifier'] = code_verifier  # Store in session
    # Create a code challenge
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")


    authorization_url, state = x_token.authorization_url(
        auth_url, code_challenge=code_challenge, code_challenge_method="S256",
    )
    session["oauth_state"] = state
    session["x_auth_type"] = "user"
    return redirect(authorization_url)


   
@login_required
@x_auth.route("/xoauth/callback", methods=["GET"])
def callback():
    code = request.args.get("code")
    x_token = make_x_token()
    code_verifier = session.get("code_verifier")
    session.pop("code_verifier", None)

    token_data = x_token.fetch_token(
        token_url=token_url,
        client_secret=config.get("X_CLIENT_SECRET"),
        code_verifier=code_verifier,
        code=code,
    )

    access_token = token_data.get('access_token')
    refresh_token = token_data.get('refresh_token')
    expires_in = int(token_data.get('expires_in', 0))
    expires_at_timestamp = int(time.time()) + expires_in
    x_auth_type = session.get('x_auth_type',None)
    repo = None
    if x_auth_type == "user":
        current_user.x_access_token_existed = True
        current_user.x_access_token_decrypted = access_token
        current_user.x_refresh_token_decrypted = refresh_token
        current_user.x_access_token_expires_at_timestamp = expires_at_timestamp
    else:
        flash('Error getting user data from Twitter', category='error')
        logging.error(f'Error getting user data from Twitter, x_auth_type was not in session.')
        db.session.rollback()
        return redirect(url_for('views.settings'))

    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    response = requests.get("https://api.twitter.com/2/users/me", headers=headers)

    # Parse the JSON response
    user_data = response.json()
    if not user_data.get('data'):
        flash('Error getting user data from Twitter', category='error')
        logging.error(f'Error getting user data from Twitter: {user_data}')
        db.session.rollback()
        return redirect(url_for('views.settings'))

    # Access specific fields
    username = user_data.get('data').get('username')
    if x_auth_type == "user":
        current_user.x_username = username
        current_user.post_to_x_active = True
        db.session.commit()
        flash('Successfully authorized posting to X', category='success')
        return redirect(url_for('views.get_profile', github_login=current_user.github_login))
    else:
        flash('Error getting user data from Twitter', category='error')
        logging.error(f'Error getting user data from Twitter, x_auth_type was not in session. second clause')
        db.session.rollback()
        return redirect(url_for('views.home'))





@login_required
@x_auth.route("/x_deauth")
def x_deauth():
    revoke_access_token_from_x(current_user)
    current_user.post_to_x_active = False
    db.session.commit()
    flash('Successfully deauthorized posting to X', category='success')
    return redirect(url_for('views.get_profile', github_login=current_user.github_login))


@x_auth.route("/x_refresh")
def x_refresh():
    refresh_access_token_from_x(current_user)
    return redirect(url_for('views.get_profile', github_login=current_user.github_login))


@login_required
@x_auth.route("/x_post_latest", methods=["GET"])
def x_post_latest():
    first_post = get_latest_post(current_user)

    payload = {"text": "{}".format(first_post)}
    response = post_to_x(current_user, first_post, current_user.x_access_token_decrypted).json()
    posted_fact = response['data']['text']
    logging.error("Posted fact: {}".format(posted_fact))
    return redirect(url_for('views.settings'))



