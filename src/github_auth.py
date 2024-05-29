from flask import Blueprint, redirect, url_for, session, request, flash, render_template, current_app
import logging,time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import requests
from pprint import pprint
from flask_login import login_user, current_user, logout_user
from sqlalchemy.exc import SQLAlchemyError

from src.utils import give_premium_to_user
from .models import User, Settings, Repo
from . import db, config
import secrets

github_auth = Blueprint('github_auth', __name__)

@github_auth.route('/login')
def login():
    # generating random state
    state = secrets.token_urlsafe(16)
    session['login_state_token'] = state
    return redirect(f'https://github.com/login/oauth/authorize?client_id={config.get("GITHUB_APP_CLIENT_ID")}&state={state}')

@github_auth.route('/github_callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')
    print("code:", code)
    print("state:", state)
    print("session state:", session.get('login_state_token'))
    if state != session.get('login_state_token'):
        print("Invalid state token")
        flash('Invalid state token, it seems that something was interfering with the login process. you could try again', 'danger')
        return redirect(url_for('views.home'))
    data = {'client_id': config.get('GITHUB_APP_CLIENT_ID'), 
            'client_secret': config.get('GITHUB_APP_CLIENT_SECRET'), 
            'code': code}
    headers = {'Accept': 'application/json'} # recently learned that this is called content negotiation:D
    response = requests.post('https://github.com/login/oauth/access_token', data=data, headers=headers)
    access_token = response.json()['access_token']
    expires_in = response.json()['expires_in']
    refresh_token = response.json()['refresh_token']
    refresh_token_expires_in = response.json()['refresh_token_expires_in']
    # transform seconds to datetimes
    access_token_expires_at_timestamp = int(time.time()) + expires_in
    print("access_token_expires_at_timestamp:", access_token_expires_at_timestamp)
    refresh_token_expires_at_timestamp = int(time.time()) + refresh_token_expires_in
    print("refresh_token_expires_at_timestamp:", refresh_token_expires_at_timestamp)



    user_data = requests.get('https://api.github.com/user', headers={'Authorization': f'token {access_token}'})
    github_id = user_data.json().get('id', None)

    github_login = user_data.json().get('login', None)
    github_name = user_data.json().get('name', None)

    user_email_data = requests.get('https://api.github.com/user/emails', headers={'Authorization': f'token {access_token}'})
    emails = user_email_data.json()
    github_email = None
    for email in emails:
        if email.get('primary', False):
            github_email = email.get('email', None)
            break
    print("github_email:", github_email)
    
    user_avatar_url = user_data.json().get('avatar_url', f'https://github.com/{github_login}.png?size=200')
    if not github_login:
        flash("Sorry, unable to get user's handle from GitHub", "danger")
        return redirect(url_for('views.home'))
    if not github_id:
        flash("Sorry, unable to get user's id from GitHub", "danger")
        return redirect(url_for('views.home'))

    if not github_name: 
        github_name = github_login

    user = User.query.filter_by(github_id=github_id).first()
    if not user:
        logging.info(f"User {github_login} not found, creating a new one")
        user = User(github_id=github_id, github_login=github_login, name=github_name, github_avatar_url=user_avatar_url)
        user.github_user_access_token_decrypted = access_token
        user.github_user_access_token_expires_at_timestamp = access_token_expires_at_timestamp
        user.github_refresh_token_decrypted = refresh_token
        user.github_refresh_token_expires_at_timestamp = refresh_token_expires_at_timestamp
        user.joining_timestamp = int(time.time())
        if github_email:
            logging.info(f"User {github_login} has an email, adding it")
            user.email_decrypted = github_email
        if 'user_timezone' in session:
            user.timezone = session['user_timezone']
        else:
            user.timezone = 'UTC'
        if 'locale' in session:
            user.locale = session['locale']
        user.settings = Settings(user_id=user.id)
        db.session.add(user)

    else:
        user.github_user_access_token_decrypted = access_token
        user.github_user_access_token_expires_at_timestamp = access_token_expires_at_timestamp
        user.github_refresh_token_decrypted = refresh_token
        user.github_refresh_token_expires_at_timestamp = refresh_token_expires_at_timestamp
        if github_email:
            user.email_decrypted = github_email
        user.github_avatar_url = user_avatar_url
        if 'user_timezone' in session and session['user_timezone'] != user.timezone:
            user.timezone = session['user_timezone']
            session.pop('user_timezone')
        user.settings = Settings(user_id=user.id)
        
    if user.github_login == "ahtavarasmus":
        user.is_admin = True
        user.premium_subscription = True

    db.session.commit()
    login_user(user, remember=True)
    return redirect(url_for('views.home'))

   
@github_auth.route('/logout')
def logout():
    session.pop('selected_repo_github_id', None)
    session.pop('selected_profile_tab', None)
    session.pop('visible_page', None)
    session.pop('repo_view_option', None)
    session.pop('tree_time_window_current', None)
    session.pop('installation_reroute', None)
    logout_user()
    
    print("Logged out")
    return redirect(url_for('views.home'))

