from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, render_template_string, Response, current_app, make_response
from time import sleep
from zoneinfo import ZoneInfo
import subprocess
from babel.dates import format_datetime
import glob
import os
import heapq
import time,logging
import hashlib
import hmac
from flask import abort
from src.tasks import process_webhook_payload

from flask_login import login_required, current_user
from sqlalchemy import func, desc

from . import db,config, get_timezone
from .models import User, Repo, Post, Month, Settings, UserRepoLastSeen, Commit, Branch, Notification, Payload
from pprint import pprint
from .utils import (create_admin_notification, create_user_notification, get_active_models_from_groq, get_last_four_parent_commits, get_last_four_posts, get_repos_for_user,get_next_posts, get_top_three_languages_for_user, give_premium_to_user, log_the_error_context, make_widget, update_user_widget_settings,set_last_seen_posts_for_new_following, make_commit_tree,verify_signature,remove_premium_from_user, create_report)
                    
from .github_utils import delete_user_profile, handle_payload, track_repo_for_user, get_installation_access_token_and_expiration_time, untrack_repo_for_user
from datetime import datetime, timedelta
import time

views = Blueprint('views', __name__)

@views.route('/server', methods=['GET'])
def server():
    return config.get('SERVER')

@views.route('/error')
def error():
    1/0
    return "error"

@views.route('/test')
def test():
    msg = "moi this is message"
    topic = "tpot"
    from .utils import send_user_email
    resp = send_user_email(current_user, topic, msg)
    print(resp)
    return resp


@views.route("/order-webhook", methods=["POST"])
def order_webhook():
    print("in order webhook")
    payload = request.json
    payload_body = request.get_data()
    print(payload)
    print("headers")
    print(request.headers)
    # Get the signature from request headers
    signature = request.headers.get("X-Signature", "")
    
    # Your webhook signing secret from Lemon Squeezy dashboard
    signing_secret = config.get("LEMON_SQUEEZY_WEBHOOK_SECRET")

    digest = hmac.new(signing_secret.encode(), payload_body, hashlib.sha256).hexdigest()
    
    # Compare signatures using secure comparison
    if not hmac.compare_digest(digest, signature):
        abort(401, "Invalid signature")

    payload = request.json
    event_name = payload["meta"]["event_name"]
    print(f"event_name: {event_name}")
    
    if event_name == "order_created":
        custom_data = payload["meta"]["custom_data"]
        user_id = int(custom_data["user_id"])
        print(f"user_id: {user_id}")
        
        user = User.query.get(user_id)
        if user:
            user.is_premium = True
            user.wants_premium = False
            db.session.commit()
            logging.info(f"User {user.github_login} is now premium")
            flash("You are now a premium user", "success")
        else:
            logging.error(f"User not found with id {user_id}")
    else:
        logging.error(f"Event name not recognized: {event_name}")
    
    return jsonify({"success": True})

@login_required
@views.route("/create-checkout", methods=["GET"])
def create_checkout():
    if config.get("SERVER") != "dev":
        current_user.is_premium = True
        db.session.commit()
        flash("You have been granted premium access for free! We're currently in beta and all features are available to everyone. Thanks for being an early supporter!", "success")
        return redirect(url_for('views.home'))
    variant_id = "649498"
    store_id = "85516"
    user_id = str(current_user.id)
    
    payload = {
        "data": {
            "type": "checkouts",
            "attributes": {
                "checkout_data": {
                    "custom": {
                        "user_id": user_id
                    }
                },
                "checkout_options": {
                    "embed": True,
                    "media": True,
                    "logo": True
                }
            },
            "relationships": {
                "store": {
                    "data": {"type": "stores", "id": store_id}
                },
                "variant": {
                    "data": {"type": "variants", "id": variant_id}
                }
            }
        }
    }
    
    url = "https://api.lemonsqueezy.com/v1/checkouts"
    import requests
    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {config.get('LEMON_SQUEEZY_API_KEY')}",
            "Content-Type": "application/json"
        },
        json=payload
    )

    print(response.json())
    if response.status_code == 201:
        checkout_url = response.json()["data"]["attributes"]["url"]
        return redirect(checkout_url)
    return "Error creating checkout", 400


@views.route('/', methods=['GET', 'POST'])
def home():
    if request.method == "POST":
        pass

    print("in home")

    session['visible_page'] = 'feed'
    visible_page = session.get('visible_page', 'feed')
    if current_user.is_authenticated:
        noti_count = Notification.query.filter_by(user_id=current_user.id, seen=False, category='user').count()
        return render_template("home.html", user=current_user, visible_page=visible_page, feed_type='main_feed_posts',noti_count=noti_count)
    return render_template("home.html", user=current_user, visible_page=visible_page, feed_type='main_feed_posts',noti_count=0,)


@views.route('/landing', methods=['GET'])
def landing():
    session['visible_page'] = visible_page = 'landing'
    return render_template("home.html", user=current_user, visible_page=visible_page, rendered_landing_page=render_template("_landing_page.html"))



@views.route('/tos-and-privacy', methods=['GET', 'POST'])
def tos_and_privacy():
    session['visible_page'] = visible_page = 'tos_and_privacy'
    return render_template("home.html", user=current_user, visible_page=visible_page, rendered_tos_and_privacy=render_template("_tos_and_privacy.html"))


#faq
@views.route('/faq', methods=['GET', 'POST'])
def faq():
    session['visible_page'] = visible_page = 'faq'
    if 'HX-Request' in request.headers and request.headers['HX-Request'] == 'true':
        return render_template("_faq.html", visible_page=visible_page)
    else:
        return render_template("home.html", user=current_user, visible_page=visible_page, rendered_faq=render_template("_faq.html", visible_page=visible_page))


@views.route('/premium', methods=['GET', 'POST'])
def premium():
    session['visible_page'] = visible_page = 'premium'

    app_url = config.get("APP_URL")

    if 'HX-Request' in request.headers and request.headers['HX-Request'] == 'true':
        return render_template("_premium.html", visible_page=visible_page, app_url=app_url)
    else:
        return render_template("home.html", user=current_user, visible_page=visible_page, rendered_premium=render_template("_premium.html", visible_page=visible_page, app_url=app_url))


@login_required
@views.route('/delete_user', methods=['GET', 'POST'])
def delete_user():
    if request.method == "POST":
        user = User.query.filter_by(id=current_user.id).first()
        if delete_user_profile(user):
            flash("User deleted successfully", "success")
        else:
            flash("Failed to delete user", "danger")
        response = make_response('', 200)
        response.headers['HX-Redirect'] = '/logout'
        return response
    return "you can delete your profile from settings page", 200

@login_required
@views.route('/delete_post/<post_id>', methods=['GET', 'POST'])
def delete_post(post_id):
    post = Post.query.filter_by(id=post_id).first_or_404()
    repo = post.commits[0].repo
    if current_user.github_login == post.commits[0].repo.owner_github_login:
        return "Unauthorized", 403

    if not post:
        return "Post not found", 404
    # also delete the commits
    for commit in post.commits:
        db.session.delete(commit)
    db.session.delete(post)

    db.session.commit()
    return "OK", 200

@login_required
@views.route('/delete_notification/<notification_id>',methods=['DELETE'])
def delete_notification(notification_id):
    if not current_user.is_admin:
        return "Unauthorized", 403
    notification = Notification.query.filter_by(id=notification_id).first()
    if not notification:
        return "Notification not found", 404
    db.session.delete(notification)
    db.session.commit()
    flash("Notification deleted", "success")
    return "OK", 200


@login_required
@views.route('/admin', methods=['GET', 'POST'])
def admin():
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return "Unauthorized", 403
    session['visible_page'] = visible_page = 'admin'
    admin_feed_type = request.args.get('admin_feed_type', 'admin-home')
    logging.info(f"admin_feed_type: {admin_feed_type}")
    if 'HX-Request' in request.headers and request.headers['HX-Request'] == 'true':
        return render_template("_admin.html", visible_page=visible_page, 
                               admin_feed_type=admin_feed_type)
    else:
        return render_template("home.html", rendered_admin=render_template("_admin.html"), 
                               user=current_user, visible_page=visible_page,
                               admin_feed_type=admin_feed_type)


@login_required
@views.route('/user-account-<action>-<user_github_id>')
def premium_to_user(action=None, user_github_id=None):
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        logging.info(f"User {current_user.github_login} tried to access the premium_to_user endpoint")
        return "Unauthorized", 403
    if not action:
        return "No action specified", 400
    #user_github_id = request.args.get('user_github_id', None)
    logging.info(f"user_github_id: {user_github_id}")
    logging.info(f"users: {User.query.all()}")
    user = User.query.filter_by(github_id=user_github_id).first()
    logging.info(f"user: {user}")
    if not user:
        logging.info(f"User not found")
        return "User not found", 404
    if action == "give":
        logging.info(f"giving premium")
        give_premium_to_user(user)
        create_user_notification(user, f"Your premium subscription has started.")
        return render_template_string("""<div class="basic-button button-sad" hx-get="/user-account-remove-{{user.github_id}}"  hx-trigger="click" hx-swap="outerHTML" hx-confirm="you are removing premium from {{user.github_login}}?">remove premium</div>""",user=user)
    elif action == "remove":
        logging.info(f"removing premium")
        remove_premium_from_user(user)
        create_user_notification(user, f"Your premium subscription has ended.")
        return render_template_string("""<div class="basic-button button-happy" hx-get="/user-account-give-{{user.github_id}}" hx-swap="outerHTML" hx-trigger="click" hx-confirm="you are removing premium from {{user.github_login}}?">give premium</div>""",user=user)
    elif action == "suspend":
        logging.info(f"suspending user")
        remove_premium_from_user(user)
        user.suspended = True
        db.session.commit()
        flash("User suspended", "success")
        create_user_notification(user, f"Your account has been suspended. Please contact support for more information.")
        return render_template_string("""<div class="basic-button button-happy" hx-get="/user-account-unsuspend-{{user.github_id}}" hx-swap="outerHTML" hx-trigger="click" hx-confirm="you are unsuspending {{user.github_login}}?">unsuspend</div>""",user=user)
    elif action == "unsuspend":
        logging.info(f"unsuspending user")
        from .utils import reactivate_user_webhooks
        reactivate_user_webhooks(user)
        user.suspended = False
        db.session.commit()
        create_user_notification(user, f"Your account has been unsuspended. Welcome back!")
        flash("User unsuspended", "success")
        return render_template_string("""<div class="basic-button button-sad" hx-get="/user-account-suspend-{{user.github_id}}"  hx-trigger="click" hx-swap="outerHTML" hx-confirm="you are suspending {{user.github_login}}?">suspend</div>""",user=user)

    else:
        logging.info(f"Action {action} not recognized")
        return "No action specified", 400

@login_required
@views.route('/suspend-user-<action>-<user_github_id>')
def suspend_user(action=None, user_github_id=None):
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        logging.info(f"User {current_user.github_login} tried to access the suspend_user endpoint")
        return "Unauthorized", 403
    if not action:
        return "No action specified", 400
    user = User.query.filter_by(github_id=user_github_id).first()
    if not user:
        logging.info(f"User not found")
        return "User not found", 404
    if action == "suspend":
        logging.info(f"suspending user")
        user.suspended = True
        db.session.commit()
        return render_template_string("""<div class="basic-button button-sad" hx-get="/suspend-user-unsuspend-{{user.github_id}}"  hx-trigger="click" hx-swap="outerHTML" hx-confirm="you are unsuspending {{user.github_login}}?">unsuspend</div>""",user=user)
    elif action == "unsuspend":
        logging.info(f"unsuspending user")
        user.suspended = False
        db.session.commit()
        return render_template_string("""<div class="basic-button button-happy" hx-get="/suspend-user-suspend-{{user.github_id}}" hx-swap="outerHTML" hx-trigger="click" hx-confirm="you are suspending {{user.github_login}}?">suspend</div>""",user=user)
    else:
        logging.info(f"Action {action} not recognized")
        return "No action specified", 400

@login_required
@views.route('/admin-home')
def admin_home():
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return "Unauthorized", 403

    session['visible_page'] = visible_page = 'admin'
    return render_template("_admin_home.html", visible_page=visible_page)

@login_required
@views.route("/get-premium-wanters")
def get_premium_wanters():
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return "Unauthorized", 403

    users = User.query.filter_by(wants_premium=True).all()

    return render_template_string('''
    <ul>
    {% for user in users %}
        <li><a href="/{{user.github_login}}>{{user.github_login}}</a><div class="basic-button" hx-get="/user-account-give-{{user.github_id}} hx-swap="outerHTML" hx-trigger="click">give</div></li>
    {% endfor %}
    </ul>
    ''', users=users)


# TODO REMOVE THIS WHEN DONE
@login_required
@views.route("/removewanters")
def removewanters():
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return "Unauthorized", 403


    for user in User.query.all():
        user.wants_premium = False
        db.session.commit()

    return "success", 200


@views.route('/load_repo_info')
def load_repo_info():
    repo_id = request.args.get('repo_id',None)
    repo = Repo.query.filter_by(id=repo_id).first()
    if not repo:
        flash('Repo not found')
        logging.error(f'Repo not found in load_repo_info for the repo id: {repo_id}')
        return "Repo not found", 404
    current_user_owner = False
    if current_user.is_authenticated:
        current_user_owner = True if current_user.github_id == repo.owner_github_id else False
    unfinished_post = Post.query.filter_by(repo_id=repo.id, author_github_id=repo.owner_github_id,not_finished=True).first()
    return render_template('_repo_info.html', repo=repo, unfinished_post=unfinished_post, current_user_owner=current_user_owner)


@login_required
@views.route('/edit-repo-desc/<repo_id>', methods=['GET'])
def edit_repo_desc(repo_id):
    repo = Repo.query.filter_by(id=repo_id).first()
    if not repo:
        return "Repo not found", 404
    if current_user.github_login != repo.owner_github_login:
        return "Unauthorized", 403
    return render_template_string('''
    <form hx-put="/save-repo-desc/{{repo.id}}" hx-target="this" hx-swap="outerHTML" class="repo-desc">
        <textarea min-width="100%" min-height="150px" name="desc">{{repo.repo_description}}</textarea>
        <button class="basic-button button-happy">Save</button>
        <button class="basic-button button-sad" hx-get="/cancel-repo-desc/{{repo.id}}">Cancel</button>
    </form>
    ''', repo=repo)

@login_required
@views.route('/cancel-repo-desc/<repo_id>', methods=['GET'])
def cancel_repo_desc(repo_id):
    repo = Repo.query.filter_by(id=repo_id).first()
    if not repo:
        return "Repo not found", 404
    if current_user.github_login != repo.owner_github_login:
        return "Unauthorized", 403
    return render_template_string('''
    <div hx-target="this" hx-swap="outerHTML" class="repo-desc">
        <p>{{repo.repo_description}}</p>
        {% if current_user_owner %}
            <button hx-get="/edit-repo-desc/{{repo.id}}" class="basic-button">
            Edit desc
            </button>
        {% endif %}
    </div>
    ''', repo=repo, current_user_owner=True)

@login_required
@views.route('/save-repo-desc/<repo_id>', methods=['PUT'])
def save_repo_desc(repo_id):
    repo = Repo.query.filter_by(id=repo_id).first()
    if not repo:
        return "Repo not found", 404
    if current_user.github_login != repo.owner_github_login:
        return "Unauthorized", 403
    new_desc = request.form.get('desc')
    repo.repo_description = new_desc
    db.session.commit()
    return render_template_string('''
    <div hx-target="this" hx-swap="outerHTML" class="repo-desc">
        <p>{{repo.repo_description}}</p>
        {% if current_user_owner %}
            <button hx-get="/edit-repo-desc/{{repo.id}}" class="basic-button">
            Edit desc
            </button>
        {% endif %}
    </div>
    ''', repo=repo, current_user_owner=True)


@login_required
@views.route('/load_user_info')
def load_user_info():
    if not current_user.is_admin:
        flash("Unauthorized", "danger")
        return "Unauthorized", 403
    user_id = request.args.get('user_id', None)
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return "User not found", 404
    logging.info(f"User {user.github_login} found")

    commits = Commit.query.filter_by(author_github_id=user.id).all()
    posts = user.posts

    # average lines changed per post(number)
    avg_lines_changed_per_post = 0
    if len(posts) > 0:
        lines_changed_sum = 0
        for post in posts:
            lines_changed_sum += post.lines_changed
        avg_lines_changed_per_post = lines_changed_sum / len(posts)

    logging.info(f"avg_lines_changed_per_post: {avg_lines_changed_per_post}")

    # average lines changed per day
    lines_changed_sum = 0
    for post in posts:
        lines_changed_sum += post.lines_changed
    avg_lines_changed_per_day = 0
    if commits:
        first_commit = commits[-1]
        last_commit = commits[0]
        total_days = (last_commit.creation_timestamp - first_commit.creation_timestamp) / 86400
        if total_days == 0:
            total_days = 1
        avg_lines_changed_per_day = lines_changed_sum / total_days
        logging.info(f"avg_lines_changed_per_day: {avg_lines_changed_per_day}")
    
    real_judging_token_count_sum = 0
    real_summary_token_count_sum = 0
    for post in posts:
        if post.judging_token_count:
            real_judging_token_count_sum += post.judging_token_count
        if post.summary_token_count:
            real_summary_token_count_sum += post.summary_token_count
    logging.info(f"post_count: {len(posts)}")
    if len(posts) > 0:
        real_judging_token_count_avg = real_judging_token_count_sum / len(posts)
        real_summary_token_count_avg = real_summary_token_count_sum / len(posts)
    else:
        real_judging_token_count_avg = 0
        real_summary_token_count_avg = 0
    logging.info(f"real_judging_token_count_avg: {real_judging_token_count_avg}")
    logging.info(f"real_summary_token_count_avg: {real_summary_token_count_avg}")
    
    # average posts per day per user when creation_timestamp is seconds
    avg_posts_per_day = 0
    if commits:
        first_post = commits[-1]
        last_post = commits[0]
        logging.info(f"first_post: {first_post}")
        total_days = (last_post.creation_timestamp - first_post.creation_timestamp) / 86400
        logging.info(f"total_days: {total_days}")
        if total_days == 0:
            total_days = 1
        logging.info(f"total_days: {total_days}")
        avg_posts_per_day = len(posts) / total_days
    logging.info(f"avg_posts_per_day: {avg_posts_per_day}")

    # post to commit ratio
    if posts and commits:
        post_to_commit_ratio = len(posts) / len(commits)
    else:
        post_to_commit_ratio = 0

    return render_template('_user_info.html', user=user, commits=commits, 
                           real_judging_token_count_avg=real_judging_token_count_avg,
                           real_summary_token_count_avg=real_summary_token_count_avg,
                           avg_posts_per_day=avg_posts_per_day,
                           avg_lines_changed_per_day=avg_lines_changed_per_day,
                           avg_lines_changed_per_post=avg_lines_changed_per_post,
                           total_commit_count=len(commits),
                           total_post_count=len(posts),
                           post_to_commit_ratio=post_to_commit_ratio)
                            

@login_required
@views.route('/change-feed-type-admin')
def change_feed_type_admin():
    admin_feed_type = request.args.get('admin_feed_type', 'home')
    print(f"Changed admin feed to {admin_feed_type}")

    return render_template("_admin.html", 
                           user=current_user, 
                           admin_feed_type=admin_feed_type,
                           visible_page='admin')


@login_required 
@views.route('/admin-error-logfile')
def admin_error_logfile():
    if current_app.debug:
        logging.info("Not getting log file in debug mode")
        return "Not getting log file in debug mode", 403
    if not current_user.is_admin:
        logging.info(f"User {current_user.github_login} tried to access the log file")
        return "Unauthorized", 403
    log_files_pattern = os.path.join(config.get('LOG_FOLDER_PATH'),'pacepeek_error*.log')
    files = glob.glob(log_files_pattern)
    if files:
        latest_file = max(files, key=os.path.getmtime)
        with open(latest_file, 'r') as file:
            lines = file.readlines()
            last_100_lines = lines[-100:]
    else:
        last_100_lines = ["No log files found."]
    return render_template('_error_log_view.html', log_lines=last_100_lines)


@login_required
@views.route('/notifications', methods=['GET', 'POST'])
def notifications():
    session['visible_page'] = visible_page = 'notifications'
    return render_template("_load_notifications.html", visible_page=visible_page)

@login_required
@views.route('/settings', methods=['GET', 'POST'])
def settings():
    session['visible_page'] = visible_page = 'settings'
    install_url = f'https://github.com/apps/{config.get("GITHUB_APP_NAME")}/installations/new'
    session['installation_reroute'] = f"/{current_user.github_login}"
    # If this is an htmx request, only send back the profile content
    logging.info(f"install url: {install_url}")
    
    newest_gpt = config.get('NEWEST_GPT_MODEL')
    newest_llama = config.get('NEWEST_LLAMA_MODEL')
    newest_mixtral = config.get('NEWEST_MIXTRAL_MODEL')

    
    groq_models = config.get('GROQ_MODELS')
    openai_models = config.get('OPENAI_MODELS')

    markdown_widget_svg = make_widget(current_user, 2, current_user.settings.markdown_widget_fill_color,current_user.settings.markdown_widget_stroke_color,current_user.settings.markdown_widget_text_color)
    app_url = config.get("APP_URL")

    if 'HX-Request' in request.headers and request.headers['HX-Request'] == 'true':
        return render_template("_settings.html", app_url=app_url,visible_page=visible_page, install_url=install_url, newest_gpt=newest_gpt, newest_llama=newest_llama, newest_mixtral=newest_mixtral, groq_models=groq_models, openai_models=openai_models, markdown_widget_svg=markdown_widget_svg)

    # If this is a direct URL access, render the home.html and include the profile content in it
    else:
        return render_template("home.html", user=current_user, visible_page='settings',rendered_settings=render_template("_settings.html", app_url=app_url, install_url=install_url,visible_page='settings', newest_gpt=newest_gpt, newest_llama=newest_llama, newest_mixtral=newest_mixtral, groq_models=groq_models, openai_models=openai_models, markdown_widget_svg=markdown_widget_svg))

@login_required
@views.route('/remove-data-<repo_github_id>', methods=['GET'])
def remove_commits(repo_github_id):
    repo = Repo.query.filter_by(github_id=repo_github_id).first()
    for commit in repo.commits:
        db.session.delete(commit)
    for post in repo.posts:
        db.session.delete(post)
    db.session.commit()
    print("removed all commits and posts from the repo")
    return redirect(url_for('views.branch_tree', repository_github_id=repo_github_id))


@views.route("/flash-messages")
def flash_messages():
    print("in flash messages")
    return render_template("_flash_messages.html")

@views.route("/search")
def get_search_view():
    session['visible_page'] = visible_page = 'search'
    users = User.query.all()

    timestamp_30_days_ago = int(time.time()) - 30 * 24 * 60 * 60
    # leaderboard
    users_ordered_by_posts = db.session.query(User, func.count(Post.id).label('post_count'))\
                            .join(User.posts)\
                            .filter(Post.creation_timestamp >= timestamp_30_days_ago)\
                            .group_by(User.id)\
                            .order_by(desc('post_count')).all()
    logging.info(f"users_ordered_by_posts: {users_ordered_by_posts}")


    rendered_search_page = render_template("_search.html", users=users, users_ordered_by_posts=users_ordered_by_posts, visible_page=visible_page)

    if 'HX-Request' in request.headers and request.headers['HX-Request'] == 'true':
        return rendered_search_page
    else:
        return render_template("home.html", visible_page=visible_page, user=current_user, rendered_search_page=rendered_search_page)


@views.route("/p/<post_id>", methods=['GET'])
def post(post_id):
    post = Post.query.filter_by(id=post_id).first_or_404()
    repo = post.commits[0].repo
    current_user_owner = False
    if current_user.github_login == post.commits[0].repo.owner_github_login:
        current_user_owner = True

    last_four_posts = get_last_four_posts(repo, post)
    rendered_last_four_posts = render_template("_posts.html", posts=last_four_posts)

    if 'HX-Request' in request.headers and request.headers['HX-Request'] == 'true':
        return render_template("_post.html", user=current_user, post=post, current_user_owner=current_user_owner,rendered_last_four_posts=rendered_last_four_posts, last_four_posts=last_four_posts)
    else:
        rendered_post = render_template("_post.html", user=current_user, post=post, current_user_owner=current_user_owner, rendered_last_four_posts=rendered_last_four_posts, last_four_posts=last_four_posts)
        return render_template("home.html", rendered_post=rendered_post, user=current_user)


@login_required
@views.route("/update-widget/<widget_type>/<dest>", methods=['POST'])
def update_widget(widget_type,dest):
    fill_color = request.form.get('fillColor', '#232626')
    stroke_color = request.form.get('strokeColor', '#0a8eb0')
    text_color = request.form.get('textColor', '#ffffff')

    update_user_widget_settings(widget_type, fill_color, stroke_color, text_color)

    svg = make_widget(current_user, 2, fill_color, stroke_color, text_color)
    res = render_template("_markdown_widget_preview.html", markdown_widget_svg=svg, user=current_user, app_url=config.get('APP_URL'))
    return res


@views.route("/reset-colors/<widget_type>/<dest>", methods=[ 'GET'])
def reset_colors(widget_type,dest):
    update_user_widget_settings(widget_type, '#232626', '#0a8eb0', '#ffffff')

    svg = make_widget(current_user, 2, '#232626', '#0a8eb0', '#ffffff')
    res = render_template("_widget_markdown.html", markdown_widget_svg=svg, user=current_user, app_url=config.get('APP_URL'))
    return res


@login_required
@views.route('/change-feed-type')
def change_feed_type():
    feed_type = request.args.get('feed_type', 'main_feed_posts')
    print(f"Changed feed to {feed_type}")

    noti_count = Notification.query.filter_by(user=current_user, seen=False,category='user').count()
    return render_template("_main_container_content.html", 
                           user=current_user, 
                           feed_type=feed_type,
                           noti_count=noti_count,
                           visible_page='feed')


@login_required
@views.route('/toggle-autom-repo-tracking')
def toggle_autom_repo_tracking():
    if current_user.settings.automatic_new_repo_tracking:
        current_user.settings.automatic_new_repo_tracking = False
    else:
        current_user.settings.automatic_new_repo_tracking = True
    db.session.commit()
    return render_template_string('''
                    <button 
                        type="button" 
                        class="basic-button"
                        hx-get="/toggle-autom-repo-tracking" 
                        hx-swap="outerHTML">
                        {% if current_user.settings.automatic_new_repo_tracking %}On{% else %}Off{% endif %}
                    </button>
    {% include '_flash_messages.html' %}
    ''')



@login_required
@views.route('/unfollow-<github_login>')
def unfollow(github_login):
    user_to_unfollow = User.query.filter_by(github_login=github_login).first()
    set_last_seen_posts_for_new_following(user_to_unfollow)
    current_user.unfollow(user_to_unfollow)
    db.session.commit()
    flash(f"You are no longer following {user_to_unfollow.name}", category='success')
    return render_template_string('''
    <button 
        type="button" 
        class="basic-button" 
        hx-get="/follow-{{github_login}}" 
        hx-swap="outerHTML">
        Follow
    </button>
    {% include '_flash_messages.html' %}
    ''', github_login=github_login)

@login_required
@views.route('/follow-<github_login>')
def follow(github_login):
    user_to_follow = User.query.filter_by(github_login=github_login).first()
    current_user.follow(user_to_follow)
    create_user_notification(user_to_follow, f"{current_user.name} started following you",f"{config.get('APP_URL')}/{current_user.github_login}")
    db.session.commit()
    flash(f"You are now following {user_to_follow.name}", category='success')
    return render_template_string('''
    <button 
        type="button" 
        class="basic-button button-happy" 
        hx-get="/unfollow-{{github_login}}" 
        hx-swap="outerHTML">
        Following
    </button>
    {% include '_flash_messages.html' %}
    ''', github_login=github_login)


@login_required
@views.route('/load_more_users_admin')
def load_more_users_admin():
    USERS_PER_PAGE = 1  
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(
            desc(User.github_login)
        ).paginate(
            page=page, per_page=USERS_PER_PAGE
        )
    next_users = users.items

    # Render the posts to HTML
    users_html = render_template('_users_admin.html', users=next_users)

    if users.has_next:
        new_page = page + 1
        load_more_html = f'''
                        <div id="load-more-container" 
                             hx-ext="preload"
                             hx-get="/load_more_users_admin?page={new_page}" 
                             hx-trigger="revealed" 
                             hx-indicator="#loading-indicator"
                             hx-swap="outerHTML">
                        </div>
                        '''
        return users_html + render_template_string(load_more_html)
    else:
        no_more_users_html = '''<div id="loading-indicator" hx-swap-oob="true">End.</div>'''
        # Return only the posts if no more pages are available and edit the indicator
        return users_html + render_template_string(no_more_users_html)


@login_required
@views.route('/load_more_payloads')
def load_more_payloads():
    PAYLOADS_PER_PAGE = 1  
    page = request.args.get('page', 1, type=int)
    payloads = Payload.query.order_by(
            desc(Payload.creation_timestamp)
        ).paginate(
            page=page, per_page=PAYLOADS_PER_PAGE
        )
    logging.info(f"payloads: {payloads}")
    next_payloads = payloads.items

    # Render to HTML
    payloads_html = render_template('_payloads.html', payloads=next_payloads)

    if payloads.has_next:
        new_page = page + 1
        load_more_html = f'''
                        <div id="load-more-container" 
                             hx-ext="preload"
                             hx-get="/load_more_payloads?page={new_page}" 
                             hx-trigger="revealed" 
                             hx-indicator="#loading-indicator"
                             hx-swap="outerHTML">
                        </div>
                        '''
        return payloads_html + render_template_string(load_more_html)
    else:
        no_more_payloads_html = '''<div id="loading-indicator" hx-swap-oob="true">End.</div>'''
        return payloads_html + render_template_string(no_more_payloads_html)


@login_required
@views.route('/load_more_notifications_admin')
def load_more_notifications_admin():
    NOTIFICATIONS_PER_PAGE = 5
    page = request.args.get('page', 1, type=int)
    notifications = Notification.query.filter_by(
            category='admin'
        ).order_by(
            desc(Notification.creation_timestamp)
        ).paginate(
            page=page, per_page=NOTIFICATIONS_PER_PAGE
        )
    next_notifications = notifications.items
    for notification in next_notifications:
        notification.seen = True
    db.session.commit()

    # Render the posts to HTML
    notifications_html = render_template('_notifications.html', notifications=next_notifications)

    if notifications.has_next:
        new_page = page + 1
        load_more_html = f'''
                        <div id="load-more-container" 
                             hx-ext="preload"
                             hx-get="/load_more_notifications_admin?page={new_page}" 
                             hx-trigger="revealed" 
                             hx-indicator="#loading-indicator"
                             hx-swap="outerHTML">
                        </div>
                        '''
        return notifications_html + render_template_string(load_more_html)
    else:
        logging.info(f"len(next_notifications): {len(next_notifications)}")
        if len(next_notifications) == 0:
            no_more_notifications_html = '''<div id="loading-indicator" hx-swap-oob="true">No more notifications</div>'''
        else:
            no_more_notifications_html = '''<div id="loading-indicator" hx-swap-oob="true"></div>'''
        # Return only the posts if no more pages are available and edit the indicator
        logging.info(f"notifications_html: {notifications_html}")
        logging.info(f"no_more_notifications_html: {no_more_notifications_html}")
        return notifications_html + render_template_string(no_more_notifications_html)

@login_required
@views.route('/get-feedback-form')
def get_feedback_form():
    limit = False
    if current_user.daily_report_count >= 5:
        limit = True

    return render_template('_feedback_report_form.html', limit=limit)

@login_required
@views.route('/submit-reports', methods=['POST'])
def submit_reports():
    message = request.form.get('feedback', None)
    if not message:
        return "Report is empty", 400
    if not current_user.daily_report_count:
        current_user.daily_report_count = 0
    if current_user.daily_report_count >= 5:
        return render_template('_feedback_report_results.html', success=False, message="You have reached the daily report limit of 5. Please use email.", content=message)
    current_user.daily_report_count += 1
    limit = False
    if current_user.daily_report_count == 5:
        limit = True
    create_report(message)
    flash("Report submitted!", category='success')
    return render_template('_feedback_report_results.html', success=True, limit=limit)

@login_required
@views.route('/load_more_notifications_report')
def load_more_notifications_report():
    """
    for loading user submitted bug/feature requests
    """
    print("in load more notifications report")
    NOTIFICATIONS_PER_PAGE = 5
    page = request.args.get('page', 1, type=int)
    print("page:", page)
    notifications = Notification.query.filter_by(
            category='report'
        ).order_by(
            desc(Notification.creation_timestamp)
        ).paginate(
            page=page, per_page=NOTIFICATIONS_PER_PAGE
        )
    next_notifications = notifications.items

    for notification in next_notifications:
        notification.seen = True
    db.session.commit()

    # Render the posts to HTML
    notifications_html = render_template('_notifications_report.html', notifications=next_notifications)

    if notifications.has_next:
        new_page = page + 1
        load_more_html = f'''
                        <div id="load-more-container" 
                             hx-ext="preload"
                             hx-get="/load_more_notifications_report?page={new_page}" 
                             hx-trigger="revealed" 
                             hx-indicator="#loading-indicator"
                             hx-swap="outerHTML">
                        </div>
                        '''
        return notifications_html + render_template_string(load_more_html)
    else:
        logging.info(f"len(next_notifications): {len(next_notifications)}")
        if len(next_notifications) == 0:
            no_more_notifications_html = '''<div id="loading-indicator" hx-swap-oob="true">No more notifications</div>'''
        else:
            no_more_notifications_html = '''<div id="loading-indicator" hx-swap-oob="true"></div>'''
        # Return only the posts if no more pages are available and edit the indicator
        logging.info(f"notifications_html: {notifications_html}")
        logging.info(f"no_more_notifications_html: {no_more_notifications_html}")
        return notifications_html + render_template_string(no_more_notifications_html)



@login_required
@views.route('/load_more_notifications')
def load_more_notifications():
    NOTIFICATIONS_PER_PAGE = 5
    page = request.args.get('page', 1, type=int)
    notifications = Notification.query.filter_by(
            user_id=current_user.id,
            category='user'
        ).order_by(
            desc(Notification.creation_timestamp)
        ).paginate(
            page=page, per_page=NOTIFICATIONS_PER_PAGE
        )
    next_notifications = notifications.items


    # Render the posts to HTML
    notifications_html = render_template('_notifications.html', notifications=next_notifications)
    print("notifications_html:", notifications_html)

    for notification in next_notifications:
        notification.seen = True
    db.session.commit()



    if notifications.has_next:
        new_page = page + 1
        load_more_html = f'''
                        <div id="load-more-container" 
                             hx-ext="preload"
                             hx-get="/load_more_notifications?page={new_page}" 
                             hx-trigger="revealed" 
                             hx-indicator="#loading-indicator"
                             hx-swap="outerHTML">
                        </div>
                        '''
        return notifications_html + render_template_string(load_more_html)
    else:
        logging.info(f"len(next_notifications): {len(next_notifications)}")
        if len(next_notifications) == 0:
            no_more_notifications_html = '''<div id="loading-indicator" hx-swap-oob="true">No more notifications</div>'''
        else:
            no_more_notifications_html = '''<div id="loading-indicator" hx-swap-oob="true"></div>'''
        # Return only the posts if no more pages are available and edit the indicator
        logging.info(f"notifications_html: {notifications_html}")
        logging.info(f"no_more_notifications_html: {no_more_notifications_html}")
        return notifications_html + render_template_string(no_more_notifications_html)


@login_required
@views.route('/load_more_repo_updates')
def load_more_repo_updates():
    """ not currently used """
    REPOS_PER_PAGE = 5  # number of repos to load per request
    page = request.args.get('page', 1, type=int)
    github_login = request.args.get('github_login', None)

    user_ids = [user[0] for user in current_user.followed.with_entities(User.id).all()]

    print("user_ids:", user_ids)
    query = db.session.query(
        Repo.id, 
        func.max(Post.creation_timestamp)
    ).join(
        Post, Post.repo_id == Repo.id
    ).join(
        User, User.id == Post.user_id
    ).filter(
        User.id.in_(user_ids)
    ).group_by(
        Repo.id
    ).order_by(
        desc(func.max(Post.creation_timestamp))
    )


    pagination = query.paginate(page=page, per_page=REPOS_PER_PAGE)
    next_repos = pagination.items

    updates = []
    for repo_id, _ in next_repos:
        last_seen = UserRepoLastSeen.query.filter_by(
                user_id=current_user.id, 
                repo_id=repo_id
        ).first()

        if last_seen:
            last_seen_post = Post.query.get(last_seen.last_seen_post_id)
            last_seen_timestamp = last_seen_post.creation_timestamp if last_seen_post else int(datetime(1970, 1, 1).timestamp())
        else:
            last_seen_timestamp = int(datetime(1970, 1, 1).timestamp())

        new_posts = Post.query.filter(
            Post.repo_id == repo_id,
            Post.creation_timestamp > last_seen_timestamp
        ).order_by(
            Post.creation_timestamp.asc()
        ).all()


        if new_posts:
            updates.append({
                'repo_id': repo_id,
                'new_posts': new_posts
            })

    
    updates_html = render_template('_updates.html', updates=updates)

    if pagination.has_next:
        new_page = page + 1
        load_more_html = f'''
                        <div id="load-more-container" 
                             hx-ext="preload"
                             hx-get="/load_more_repo_updates?page={new_page}&github_login={github_login}" 
                             hx-trigger="revealed" 
                             hx-indicator="#loading-indicator"
                             hx-swap="outerHTML">
                        </div>
                        '''
        return updates_html + render_template_string(load_more_html)
    else:
        if len(updates) == 0:
            no_more_posts_html = '''<div id="loading-indicator" hx-swap-oob="true">You are up to date :)</div>'''
        else:
            no_more_posts_html = '''<div id="loading-indicator" hx-swap-oob="true"></div>'''
        # Return only the posts if no more pages are available and edit the indicator
        return updates_html + render_template_string(no_more_posts_html)


POSTS_PER_PAGE = 5

@views.route('/load_more_posts')
def load_more_posts():
    # Get page number from URL parameter
    page = request.args.get('page', 1, type=int)
    github_login = request.args.get('github_login', None)
    repo_github_id = request.args.get('repo_github_id', None)
    feed_type = request.args.get('feed_type', "main_feed_posts")
    print("feed_type", feed_type)

    if feed_type == "profile":
        user = User.query.filter_by(github_login=github_login).first()
        user_ids = [user.id]
        # Fetch posts using pagination
        logging.info(f"fetching posts for user: {user.github_login}")
        for post in Post.query.filter_by(user=user).all():
            logging.info(f"post: {post.author_github_id}")
        pagination = Post.query \
                    .join(Post.repo) \
                    .filter(
                        Post.not_finished == False, 
                        Post.author_github_id == user.github_id
                    ) \
                    .order_by(
                        Post.creation_timestamp.desc()
                    ) \
                    .paginate(
                        page=page, per_page=POSTS_PER_PAGE
                    )
        logging.info(f"pagination: {pagination} on profile")
    elif feed_type == "main_feed_posts":
        user_ids = [user[0] for user in current_user.followed.with_entities(User.id).all()]
        # Fetch posts using pagination
        pagination = Post.query \
                        .join(Post.repo) \
                        .filter(
                            Post.not_finished == False, 
                            Post.user_id.in_(user_ids)
                        ) \
                        .order_by(
                            Post.creation_timestamp.desc()
                        ) \
                        .paginate(
                            page=page, per_page=POSTS_PER_PAGE
                        )

    else:
        return "Invalid feed type", 400

    logging.info(f"pagination: {pagination}")
    next_posts = pagination.items
    logging.info(f"next_posts: {next_posts}")

    # Render the posts to HTML
    posts_html = render_template('_posts.html', posts=next_posts, feed_type=feed_type)
    logging.info(f"posts_html: {posts_html}")

    if pagination.has_next:
        logging.info("has next")
        new_page = page + 1
        load_more_html = f'''
                        <div id="load-more-container" 
                             hx-ext="preload"
                             hx-get="/load_more_posts?page={new_page}&github_login={github_login}&feed_type={feed_type}" 
                             hx-trigger="revealed" 
                             hx-indicator="#loading-indicator"
                             hx-swap="outerHTML">
                        </div>
                        '''
        return posts_html + render_template_string(load_more_html)
    else:
        logging.info("no next")
        if feed_type == 'profile':
            user = User.query.filter_by(github_login=github_login).first()
            if len(user.posts) == 0:
                if user.id == current_user.id:
                    no_more_posts_html = '''<div id="loading-indicator" hx-swap-oob="true">You have no posts yet</div>'''
                else:
                    no_more_posts_html = '''<div id="loading-indicator" hx-swap-oob="true">This hacker has no posts yet</div>'''
                return posts_html+ render_template_string(no_more_posts_html)

        if user_ids == [] and feed_type == 'main_feed_posts':
            no_more_posts_html = '''<div id="loading-indicator" hx-swap-oob="true">Start following some users and their posts will appear here!</div>'''
        else:
            no_more_posts_html = '''<div id="loading-indicator" hx-swap-oob="true">You have reached the end!</div>'''
        # Return only the posts if no more pages are available and edit the indicator
        return posts_html + render_template_string(no_more_posts_html)


@views.route('/search-results', methods=['POST', 'GET'])
def search_results():
    """
    returns a list of users that match the search term
    """

    search_term = request.args.get('search', '')

    print("search term:", search_term)
    users = User.query.filter(User.github_login.like(f"%{search_term}%")).all()
    lang = Post.query.filter(Post.programming_language.like(f"%{search_term}%")).first()
    lang = lang.programming_language if lang else None
    logging.info(f"lang: {lang}")
    if lang:
        users_with_most_posts_in_lang = (
            db.session.query(User, func.count(Post.id).label('post_count'))
            .join(Post, User.github_id == Post.author_github_id)
            .filter(Post.programming_language == lang)
            .group_by(User)
            .order_by(db.desc('post_count')).limit(3).all()
        )
    else:
        users_with_most_posts_in_lang = []
    if search_term == '':
        return render_template('_search_results.html', people=[])

    return render_template('_search_results.html', people=users, users_with_most_posts_in_lang=users_with_most_posts_in_lang, lang=lang)


@login_required
@views.route('/get-repos-user',methods=['GET'])
def get_repos_user():
    if current_user.suspended:
        logging.info("suspended user")
        flash("Your account is suspended", category='error')
        return "Unauthorized", 403
    selected_tab = request.args.get('selected_tab', 'Tracked repositories')
    
    logging.info("repos for user") 
    repos = get_repos_for_user()
    if not repos:
        flash("Couldn't get the user's repositories", category='error')
        logging.info("Couldn't get the user's repositories")
    
    repo_options = "\n".join('''<div class="repo-option">
                <label class="custom-checkbox-label">
                    <input type="checkbox" class="repo-checkbox custom-checkbox" name="repos" value="{}|{}|{}|{}">
                    <span class="repo-label custom-checkbox-box"></span>
                    <span class="repo-name">{}</span>
                </label>
            </div>'''.format(repo['owner_id'], repo['github_id'], repo['name'],repo['private'], repo['name']) for repo in repos)


    form_html = '''
    <div class="back-button" hx-trigger="click" hx-get="/{{current_user.github_login}}" hx-target=".main-container" style="cursor: pointer;">&#8592; Back</div>
    {% if repos %}
    <div class="repo-list-container">
        </form>
        <form id="checked-repos" class="repo-form">
            <div class="repo-options-container">
                {{ repo_options|safe }}
            </div>
        </form>
        <button class="basic-button repo-track-button" hx-post="/add-user-repos-to-tracking"
                hx-include="#checked-repos"
                hx-swap="innerHTML"
                hx-target=".content"
                hx-trigger="click once"
                hx-indicator="#loadingIcon">Start Tracking</button>
    </div>
    {% else %}
    <p class="no-repos">No repositories found</p>
    {% endif %}
    '''
    logging.info(f"repos: {repos}")
    whole_page = render_template_string(form_html,
                                        repo_options=repo_options, 
                                        repos=repos)
    logging.info(f"whole_page: {whole_page}")
    return whole_page


@login_required
@views.route('/add-repo-to-tracking')
def add_repo_to_tracking():
    repo_github_id = request.args.get("repo_github_id")
    repo_name = request.args.get("repo_name")
    repo_private = request.args.get("repo_private")
    user_id = request.args.get("user_id")
    if current_user.id != user_id:
        flash("Unauthorized", "warning")
        return redirect(url_for('views.home'))
    hook_id = track_repo_for_user(repo_name, repo_github_id, repo_private)
    if not hook_id:
        flash("Sorry something went wrong", "error")
        abort(401, "Couldn't add single repo to tracking")

    flash(f"Success! {repo_name} is now being tracked.")
    return redirect(url_for('views.home'))


    

@login_required
@views.route('/add-user-repos-to-tracking', methods=['POST'])
def add_user_repos_to_tracking():
    try:
        selected_repos = request.form.getlist('repos')
        print("selected_repos:", selected_repos)

        if not selected_repos:
            flash("Please select a repository first")
            return get_profile(current_user.github_login)

        fail = 0 
        success_repo_names = []
        failure_repo_names = []
        for new_repo in selected_repos:
            repo_owner_github_id, repo_github_id, repo_name, repo_private = new_repo.split('|')

            print("repo_owner_github_id:",repo_owner_github_id)
            print("repo_name:",repo_name)
            print("repo_github_id:",repo_github_id)
            print("repo_private:",repo_private)
            if repo_private == 'True': 
                repo_private = True
            else:
                repo_private = False
            hook_id = track_repo_for_user(repo_name, repo_github_id, repo_private)
            if not hook_id:
                flash("Error tracking the repo: {}".format(repo_name), category='error')
                failure_repo_names.append(repo_name)
                fail += 1
            else:
                success_repo_names.append(repo_name)

        if not failure_repo_names:
            flash("Successfully added {} repositories to tracking!".format(len(selected_repos)), category='success')
        else:
            flash("Successfully added {} repositories to tracking, {} failed.".format(len(selected_repos) - fail, fail))

        return redirect(url_for('views.get_profile', github_login=current_user.github_login, selected_tab='Tracked repositories'))
    except Exception as e:
        logging.error(f"Error in add-user-repos-to-tracking: {e}")
        log_the_error_context(e,100,f"Error in add-user-repos-to-tracking: {e}")
        return redirect(url_for('views.get_profile', github_login=current_user.github_login, selected_tab='Tracked repositories'))


@login_required
@views.route('/untrack/<string:owner_github_login>/<string:repo_name>')
def untrack_repo(owner_github_login, repo_name):
    if current_user.github_login != owner_github_login:
        return "Unauthorized", 403

    if not untrack_repo_for_user(repo_name):
        flash("Error untracking the repo: {}".format(repo_name), category='error')
    else:
        flash(f"Removed {repo_name} from your tracking list, data for that repo is saved still.", category='success')
    return "", 200


def verify_signature(payload_body, secret_token, signature_header):
    if not signature_header:
        abort(403, description="x-hub-signature-256 header is missing!")

    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        logging.error(f"Request signatures didn't match! {expected_signature} != {signature_header}")
        abort(403, description="Request signatures didn't match!")


def handle_push_event(payload, payload_body, signature_header):
    verify_signature(payload_body, config.get('GITHUB_REPOSITORY_WEBHOOK_SECRET'), signature_header)
    if 'commits' in payload:
        if config.get('SERVER') == "dev":
            handle_payload(payload)
            return '', 200

        payload_obj = Payload(content=payload,creation_timestamp=int(time.time()))
        db.session.add(payload_obj)
        db.session.commit()
        logging.info(f"payload stored successfully")
        process_webhook_payload.apply_async(args=[payload_obj.id], countdown=2)
        logging.info(f"payload sent to celery")
        return {'message': f'Processed push event with {len(payload["commits"])} commits'}
    else:
        logging.info(f"no commits in payload")


def handle_ping_event(payload, payload_body, signature_header):
    verify_signature(payload_body, config.get('GITHUB_REPOSITORY_WEBHOOK_SECRET'), signature_header)
    logging.info("ping event")
    if 'hook' in payload:
        hook_status = payload['hook']['active']
        if hook_status:
            logging.info("hook is active")
        else:
            logging.info("hook is inactive")

    return '', 200


def handle_user_installation_event(payload, installation_id, account_github_login, account_github_id, sender_github_login, sender_github_id):
    sender = User.query.filter_by(github_id=sender_github_id).first()
    if not sender:
        logging.info(f"user not found when trying to create installation or update permissions")
        return '', 404

    logging.info(f"installation is for a user, updating user with id: {account_github_id} and name: {account_github_login}")
    sender.github_installation_id = installation_id
    token, expires_at = get_installation_access_token_and_expiration_time(installation_id)
    sender.github_installation_access_token_decrypted = token
    sender.github_installation_access_token_expires_at = expires_at


    create_user_notification(sender, f"PacePeek has been installed to your GitHub account {account_github_login} and you are ready to track your personal repos now!")
    logging.info(f"Successfully created user app installation with id: {account_github_id} and name: {account_github_login}")
    db.session.commit()


def handle_user_installation_deleting_event(payload, installation_id, account_github_login, account_github_id, sender_github_login, sender_github_id):
    sender = User.query.filter_by(github_id=sender_github_id).first()
    if not sender:
        logging.info("No sender found for user")
        return '', 404
    sender.github_installation_id = None
    sender.github_installation_access_token_exists = False
    create_user_notification(sender, f"Your PacePeek github app installation for {account_github_login} has been deleted")
    logging.info(f"user installation_id deleted")


def handle_installation_event(payload, payload_body, signature_header):
    verify_signature(payload_body, config.get('GITHUB_APP_WEBHOOK_SECRET'), signature_header)
    if 'action' not in payload:
        logging.error(f"action not in payload")
        return '', 400

    if payload['action'] == 'created' or payload['action'] == 'new_permissions_accepted':
        installation_id = payload['installation']['id']

        account_github_login = payload['installation']['account']['login']
        account_github_id = payload['installation']['account']['id']
        account_type = payload['installation']['account']['type']

        sender_github_login = payload['sender']['login']
        sender_github_id = payload['sender']['id']

        if account_type == 'User':
            handle_user_installation_event(payload, installation_id, account_github_login, account_github_id, sender_github_login, sender_github_id)
        else:
            logging.error(f"account_type is not user, but: {account_type}")
            create_admin_notification(f"account_type is not user, but: {account_type}")
        db.session.commit()

    elif payload['action'] == 'deleted':
        installation_id = payload['installation']['id']

        account_github_login = payload['installation']['account']['login']
        account_github_id = payload['installation']['account']['id']
        account_type = payload['installation']['account']['type']

        sender_github_login = payload['sender']['login']
        sender_github_id = payload['sender']['id']

        if account_type == 'User':
            logging.info(f"installation is for a user")
            handle_user_installation_deleting_event(payload, installation_id, account_github_login, account_github_id, sender_github_login, sender_github_id)
        else:
            logging.error(f"when deleting account_type is not user, but: {account_type}")
            create_admin_notification(f"when deleting account_type is not user, but: {account_type}")
        db.session.commit()

    else:
        logging.info(f"action not recognized")



def handle_repository_event(payload, payload_body, signature_header):
    verify_signature(payload_body, config.get('GITHUB_APP_WEBHOOK_SECRET'), signature_header)
    action = payload.get('action')

    from .github_utils import untrack_repo_for_user_installation_token

    if action in ['archived', 'deleted']:
        repo = Repo.query.filter_by(github_id=payload['repository']['id']).first()
        if not repo: 
            return '', 200
        user = User.query.filter_by(github_id=repo.owner_github_id).first()
        if not user: 
            return '', 200
        repo.archived = True
        db.session.commit()

        untrack_repo_for_user_installation_token(repo, user)
        logging.info(f"deactivated hooks for {repo.name} for user {user.name}")
    elif action == 'renamed':
        repo_github_id = payload['repository']['id']
        repo = Repo.query.filter_by(github_id=repo_github_id).first()
        if not repo: 
            return '', 200
        repo.name = payload['repository']['name']
        db.session.commit()
        logging.info(f"changed repository name from {payload['changes']['repository']['name']['from']} to {payload['repository']['name']}")
    elif action == 'transferred':
        repo_github_id = payload['repository']['id']
        repo = Repo.query.filter_by(github_id=repo_github_id).first()
        if not repo:
            return '', 200
        user = User.query.filter_by(github_id=repo.owner_github_id).first()
        if not _user:
            return '', 200
        untrack_repo_for_user_installation_token(repo, user)
        db.session.delete(repo)
        db.session.commit()
        logging.info(f"transferred repository {repo.name} from {user.name} to new owner so untracked")
    elif action == 'unarchived':
        repo_name = payload['repository']['name']
        repo_github_id = payload['repository']['id']
        repo_private = payload['repository']['private']
        owner_github_id = payload['repository']['owner']['id']
        repo = Repo.query.filter_by(github_id=repo_github_id).first()
        if not repo:
            return '', 200
        user = User.query.filter_by(github_id=repo.owner_github_id).first_or_404()
        create_user_notification(user, f"Repo '{repo.name}' was unacrhived. Click to start tracking it again!", f"{config.get('APP_URL')}/add-repo-to-tracking?repo_github_id={repo_github_id}&repo_name={repo_name}&repo_private={repo_private}&user_id={user.id}")
    elif action == 'created':
        repo_name = payload['repository']['name']
        repo_github_id = payload['repository']['id']
        repo_private = payload['repository']['private']
        owner_github_id = payload['repository']['owner']['id']
        user = User.query.filter_by(github_id=owner_github_id).first_or_404()
        if user.settings.automatic_new_repo_tracking:
            hook_id = track_repo_for_user(repo_name, repo_github_id, repo_private)
            if not hook_id:
                create_user_notification(user, f"Failed to start tracking the new repo '{repo_name}'. Try again by clicking this notification.", f"{config.get('APP_URL')}/add-repo-to-tracking?repo_github_id={repo_github_id}&repo_name={repo_name}&repo_private={repo_private}&user_id={user.id}")
            else:
                create_user_notification(user, f"Started tracking the new repo '{repo_name}'!")
        else:
            create_user_notification(user, f"You created a new repo '{repo_name}' in GitHub. Click to start tracking it!", f"{config.get('APP_URL')}/add-repo-to-tracking?repo_github_id={repo_github_id}&repo_name={repo_name}&repo_private={repo_private}&user_id={user.id}")
    elif action == "publicized" or action == "privatized":
        repo_github_id = payload['repository']['id']
        repo_private = payload['repository']['private']
        repo = Repo.query.filter_by(github_id=repo_github_id).first_or_404()
        if repo.private != repo_private:
            repo.private = repo_private
            db.session.commit()
       
    # left are:
    # edited - The topics, default branch, description, or homepage of a repository was changed.

    return '', 200


                

event_handlers = {
    'ping': handle_ping_event, # for setting repo webhooks
    'push': handle_push_event, # for processing commits
    'installation': handle_installation_event, # for handling github app installations/deletions
    'repository': handle_repository_event, # repos state is altered: archived, created, deleted, edited, renamed, transferred, unacrhived
}

@views.route('/webhook', methods=['POST'])
def webhook():
    payload = request.json
    headers = request.headers
    logging.info("headers:")
    pprint(headers)
    logging.info("payload:")
    pprint(payload)
    # Retrieve the request's body and the X-Hub-Signature-256 header
    signature_header = request.headers.get('X-Hub-Signature-256')
    logging.info(f"signature_header: {signature_header}")
    event_type = request.headers.get('X-GitHub-Event')
    logging.info(f"event_type: {event_type}")
    if not payload:
        return '', 400
    payload_body = request.get_data()


    if event_type in event_handlers:
        event_handler = event_handlers[event_type]
        response = event_handler(payload, payload_body, signature_header)
    else:
        response = {'error': 'Unsupported event type'}

    return jsonify(response)


@views.route('/widget_svg/<github_login>/<int:number_of_posts>/', methods=['GET'])
def widget_svg(github_login=None, number_of_posts=3):
    if not github_login:
        return '', 400
    user = User.query.filter_by(github_login=github_login).first()
    if not user:
        return '', 404
    if user.suspended:
        return '', 403
    fill_color = request.args.get('fill_color', None) 
    stroke_color = request.args.get('stroke_color', None)
    text_color = request.args.get('text_color', None)
    if not fill_color or not stroke_color or not text_color:
        fill_color = user.settings.markdown_widget_fill_color
        stroke_color = user.settings.markdown_widget_stroke_color
        text_color = user.settings.markdown_widget_text_color
    else:
        fill_color = "#" + fill_color
        stroke_color = "#" + stroke_color
        text_color = "#" + text_color

    if int(number_of_posts) > 10:
        number_of_posts = 3

    latest_posts_count = int(number_of_posts)

    svg = make_widget(user,latest_posts_count, fill_color, stroke_color, text_color)

    return Response(svg, content_type='image/svg+xml')


@views.route('/installation_reroute', methods=['GET'])
def installation_reroute():
    if "installation_reroute" in session:
        sleep(2)
        return redirect(session['installation_reroute'])
    return redirect(url_for('views.home'))


@views.route('/<github_login>')
def get_profile(github_login=None):
    if not github_login:
        flash("Please provide a github login")
        return redirect(url_for('views.home'))
    user = User.query.filter_by(github_login=github_login).first()
    if not user:
        flash("User not found")
        return redirect(url_for('views.home'))

    if current_user.is_authenticated:
        is_following = current_user.is_following(user)
    else:
        is_following = False

    
    selected_profile_tab = request.args.get('selected_profile_tab', None)
    if not selected_profile_tab:
        recent_profile_tab = session.get('selected_profile_tab', None)
        if recent_profile_tab:
            selected_profile_tab = recent_profile_tab
        else:
            selected_profile_tab = 'user_posts'
    posts = repos = markdown_widget_svg = None
    if selected_profile_tab == 'user_posts':
        posts = Post.query.filter_by(user_id=user.id, not_finished=False).order_by(Post.creation_timestamp.desc()).all()
        session['selected_profile_tab'] = 'user_posts'
    elif selected_profile_tab == 'tracked_repos':
        commit_count_subquery = (
            db.session.query(Repo.id, func.count(Commit.id).label('commit_count'))
           .join(Commit)  # No longer filtering by commit creation timestamp
           .group_by(Repo.id)
           .subquery()
        )
        repos = (
                db.session.query(Repo, commit_count_subquery.c.commit_count)
           .filter_by(owner_github_id=user.github_id, deleted=False)
           .outerjoin(commit_count_subquery, Repo.id == commit_count_subquery.c.id)  # Changed to left_join
           .order_by(desc(commit_count_subquery.c.commit_count))  # Ordering remains the same
           .all()
        )
        
        
        session['selected_profile_tab'] = 'tracked_repos'
    elif selected_profile_tab == "user_settings":
        markdown_widget_svg = make_widget(user, 2, user.settings.markdown_widget_fill_color,user.settings.markdown_widget_stroke_color,user.settings.markdown_widget_text_color)
        session['selected_profile_tab'] = 'user_settings'


    top_three_languages_for_user = get_top_three_languages_for_user(user)
    

    session['visible_page'] = 'profile'
    visible_page = 'profile'

    install_url = f'https://github.com/apps/{config.get("GITHUB_APP_NAME")}/installations/new'
    session['installation_reroute'] = f"/{github_login}"

    rendered_profile_page = render_template("_profile_content.html", user=user, repos=repos, posts=posts, is_following=is_following, selected_profile_tab=selected_profile_tab, feed_type='profile', markdown_widget_svg=markdown_widget_svg, visible_page=visible_page, install_url=install_url, app_url=config.get('APP_URL'), top_three_languages_for_user=top_three_languages_for_user)

    # If this is an htmx request, only send back the profile content
    if 'HX-Request' in request.headers and request.headers['HX-Request'] == 'true':
        return rendered_profile_page

    # If this is a direct URL access, render the home.html and include the profile content in it
    else:
        return render_template("home.html", rendered_profile=rendered_profile_page, user=current_user, visible_page='profile')


@views.route('/update_timezone', methods=['POST'])
def update_timezone():
    data = request.json
    if data:
        user_timezone = data.get('timezone')
        if user_timezone:
            if current_user.is_authenticated:
                current_user.timezone = user_timezone
                db.session.commit()
            else:
                session['user_timezone'] = user_timezone

            return jsonify({'status': 'success', 'timezone': user_timezone})
    return jsonify({'status': 'error', 'message': 'Timezone not provided'}), 400

# Custom Error Handler
@views.errorhandler(404)
def page_not_found(e):
    return render_template("home.html", rendered_error_page=render_template('404.html', description=e.description)), 404


@views.errorhandler(403)
def forbidden(error):
    return render_template("home.html", rendered_error_page=render_template('403.html', description=error.description)),  403
