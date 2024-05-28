from src.x_utils import post_daily_summary_to_x
from .utils import create_admin_notification, create_user_notification, log_the_error_context
from .models import User, Post, Repo
from datetime import datetime, timedelta
from celery import shared_task
from flask import current_app
from . import db, config
from .github_utils import handle_payload
from .models import Payload
import logging, time

@shared_task
def every_minute():
    print('every_minute**********************')
    logging.info('every_minute**********************')
    #create_user_notification(User.query.filter_by(github_login='ahtavarasmus').first(), 'every_minute')

@shared_task
def process_webhook_payload(payload_id):
    # Retrieve the payload from the database using payload_id
    payload = Payload.query.get(payload_id)
    # Process the payload
    success = handle_payload(payload.content)
    logging.info(f'payload processed with success: {success}')
    if success:
        payload.status = 'success'
        # remove the payload from the db
        db.session.delete(payload)
        db.session.commit()
        logging.info('payload processed successfully and removed from db')
    else:
        payload.status = 'failed'
        db.session.commit()
        logging.error('payload processing failed')

@shared_task
def beginning_of_month():
    print('beginning_of_month**********************')
    logging.info('beginning_of_month**********************') 
    #posts_older_than_month = 
    # Extract the summaries from the posts
    #summaries = [post.content for post in posts_older_than_month]

@shared_task
def every_midnight():
    print('every_midnight**********************')
    logging.info('every_midnight**********************')

    posts_older_than_2months = Post.query.filter(Post.creation_timestamp < int(time.time()) - 60*60*24*30*2).all()
    for post in posts_older_than_2months:
        db.session.delete(post)
        logging.info(f'deleted post with id {post.id}')
    db.session.commit()
    logging.info('deleted posts older than 2 months')


def send_summary_every_day():
    # TODO this wold be turned into summary making machine
    # every hour task would then send these summaries to X
    print('every_hour day check**********************')
    logging.info('every_hour day check**********************')
