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
import requests

@shared_task
def every_minute():
    print('eevery_minute**********************')
    logging.info('every_minute**********************')
    #create_user_notification(User.query.filter_by(github_login='ahtavarasmus').first(), 'every_minute')

@shared_task(bind=True, autoretry_for=(Exception,), max_retries=3, retry_backoff=True)
def process_webhook_payload(self, payload_id):
    # TODO this retry logic is will not work yet and need to be tested and refactored
    try:
        # Retrieve the payload from the database using payload_id
        from . import db
        payload = None
        # Use a transaction only for fetching and deleting the payload
        with db.session.begin():
            payload = db.session.query(Payload).get(payload_id)
            if not payload:
                logging.info(f"No payload found with id {payload_id}")
                return False

        # Process the payload outside the transaction
        success = handle_payload(payload.content)

        # Use another transaction for deletion
        if success:
            with db.session.begin():
                db.session.delete(payload)
                logging.info(f"Successfully processed and deleted payload {payload_id}")
        else:
            logging.error(f"Failed to process payload {payload_id}")
        return success
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            raise self.retry(exc=e, countdown=2 ** self.request.retries)
        else:
            raise e
    except Exception as e:
        # Retry on other exceptions, e.g., database issues
        raise self.retry(exc=e, countdown=60, max_retries=3)

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
