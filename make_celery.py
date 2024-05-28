from src import create_app

# make another app instance for celery
flask_app = create_app()
# get the celery instance from the app
celery_app = flask_app.extensions['celery']
# push the application context to the app so we can use current_app
flask_app.app_context().push()
if __name__ == '__main__':
    # run the celery worker
    celery_app.worker_main(['worker', '-B', '-l', 'info'])

# teh celery_app variable is taken from this file and run with daemon:
# celery -A make_celery:celery_app worker -B -l info
# the -B flag is for the beat scheduler which is important for scheduling tasks
# in .service file:
"""
[Unit]
Description=Celery worker for pacepeek blue 
After=network.target

[Service]
Type=simple
User=rasmus
Group=rasmus
WorkingDirectory=/home/rasmus/blue/pacepeek
ExecStart=/home/rasmus/blue/pacepeek/venv/bin/celery -A make_celery:celery_app worker --loglevel=info -B
ExecStop=/home/rasmus/blue/pacepeek/venv/bin/celery multi stopwait worker -A make_celery:celery_app --loglevel=INFO
Restart=always

[Install]
WantedBy=multi-user.target
"""

