import sentry_sdk
from flask import Flask, current_app, request, session
from flask_cors import CORS
from flask_login import LoginManager, current_user, login_user
from flask_migrate import Migrate
from celery import Celery, Task, shared_task
from celery.schedules import crontab
import logging
from logging.handlers import RotatingFileHandler


import os
from flask_sqlalchemy import SQLAlchemy
import json


with open('/etc/pacepeek_config.json') as config_file:
    config = json.load(config_file)

db = SQLAlchemy()
DB_NAME = config.get('DB_NAME')

migrate = Migrate()

sentry_sdk.init(
    dsn="https://5d9dea42b50fd392f9e09da75acce9d4@o4507415184539648.ingest.de.sentry.io/4507415211868240",
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    traces_sample_rate=1.0,
    # Set profiles_sample_rate to 1.0 to profile 100%
    # of sampled transactions.
    # We recommend adjusting this value in production.
    profiles_sample_rate=1.0,
)

def get_timezone():
    if current_user.is_authenticated:
        return current_user.timezone
    return 'UTC'


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config.get('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = config.get('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    migrate.init_app(app,db)
   
    app.config['CELERY_BROKER_URL'] = 'amqp://localhost:5672'
    app.config.from_mapping(CELERY=dict(
            broker_url='amqp://localhost:5672',
            task_ignore_result=True,
        ),
    )

    celery_init_app(app)

    app.jinja_env.line_statement_prefix = '#'
    app.jinja_env.autoescape = True

    from .views import views 
    from .github_auth import github_auth
    from .x_auth import x_auth
    from .models import User,Post
    from .template_filters import template_filters
    
    # cross origin resource sharing for widgets
    CORS(app)
    app.register_blueprint(views)
    app.register_blueprint(github_auth)
    app.register_blueprint(x_auth)
    app.register_blueprint(template_filters)


    if not os.path.exists(config.get('SQLITE_DATABASE_PATH')):
        with app.app_context():
            db.create_all()
        logging.info('Created Database!')

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    if config.get('DEBUG') == "False":
        app.debug = False
    else:
        app.debug = True



    configure_logging(app)

    @app.errorhandler(Exception)
    def handle_all_errors(e):
        current_app.logger.error(f"An error occurred: {e}")
        return str(e), 500



    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))



    return app



def configure_logging(app):
    if config.get('DEBUG') == "False":
        # Get the root logger
        root_logger = logging.getLogger()

        # Set the log level to INFO
        root_logger.setLevel(logging.INFO)

        # Create a Rotating File Handler for INFO level messages
        info_handler = RotatingFileHandler(
            os.path.join(config.get('LOG_FOLDER_PATH'), 'pacepeek_info.log'),
            maxBytes=10000000,  # 10 MB
            backupCount=5)      # Keep 5 backup files
        info_handler.setLevel(logging.INFO)

        # Create a Rotating File Handler for ERROR level messages
        error_handler = RotatingFileHandler(
            os.path.join(config.get('LOG_FOLDER_PATH'), 'pacepeek_error.log'),
            maxBytes=10000000,  # 10 MB
            backupCount=5)      # Keep 5 backup files
        error_handler.setLevel(logging.ERROR)

        # Create a formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        info_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)

        # Add the handlers to the root logger
        root_logger.addHandler(info_handler)
        root_logger.addHandler(error_handler)

def celery_init_app(app: Flask) -> Celery:
    from . import tasks
    class FlaskTask(Task):
        def __call__(self, *args: object, **kwargs: object) -> object:
            with app.app_context():
                return self.run(*args, **kwargs)

    celery_app = Celery(app.name, task_cls=FlaskTask)
    celery_app.config_from_object(app.config['CELERY'])
    celery_app.conf.update(timezone='UTC')
    celery_app.conf.task_acks_late = True

    celery_app.set_default()

    celery_app.conf.beat_schedule = {
        'every_minute_task': {
            'task':'src.tasks.every_minute',
            'schedule': crontab(minute='*')
        },
        'beginning_of_month_task': {
            'task': 'src.tasks.beginning_of_month',
            'schedule': crontab(minute='0', hour='0', day_of_month='1')
        },
        'send_summary_every_day_task': {
            'task': 'src.tasks.send_summary_every_day',
            'schedule': crontab(minute='0') # check every hour for different day times
        },
        'every_midnight_task': {
            'task': 'src.tasks.every_midnight',
            'schedule': crontab(minute='0', hour='0')
        }
    }
    
    #@celery_app.on_after_configure.connect
    #def setup_periodic_tasks(sender,**kwargs):
    #    #from .tasks import every_minute 
    #    sender.add_periodic_task(crontab(),every_minute.s())

    app.extensions["celery"] = celery_app
    return celery_app

