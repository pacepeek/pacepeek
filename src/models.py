from . import db,config
import json
from datetime import datetime
from zoneinfo import ZoneInfo
from flask_login import UserMixin
from cryptography.fernet import Fernet
from sqlalchemy.sql import func

from sqlalchemy import MetaData


def get_key():
    key = config.get('ENCRYPT_KEY').encode()
    return key

def encrypt_item(message: str):
    key = get_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_item(encrypted_message: bytes):
    key = get_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

# Define a tracking association table
trackers = db.Table('trackers',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('repo_id', db.Integer, db.ForeignKey('repo.id'))
)

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    email_encrypted = db.Column(db.String,nullable=True)
    timezone = db.Column(db.String(100), nullable=True)
    github_id = db.Column(db.String(120), unique=True, nullable=False)
    github_login = db.Column(db.String(120), unique=True, nullable=False, index=True)
    suspended = db.Column(db.Boolean, default=False)
    suspended_reason = db.Column(db.String(500))
    creation_timestamp = db.Column(db.Integer, index=True)
    language = db.Column(db.String(50), default='en')
    joining_timestamp = db.Column(db.Integer, index=True)


    # daily report limit is 5 reports
    daily_report_count = db.Column(db.Integer, default=0)

    
    # access token
    github_user_access_token_encrypted = db.Column(db.String)
    github_user_access_token_expires_at_timestamp = db.Column(db.Integer, index=True)
    github_refresh_token_encrypted = db.Column(db.String, default=None)
    github_refresh_token_expires_at_timestamp = db.Column(db.Integer, index=True)

    # installation token
    github_installation_id = db.Column(db.Integer, nullable=True)
    github_installation_access_token_exists = db.Column(db.Boolean, default=False)
    github_installation_access_token_encrypted = db.Column(db.String, default=None)
    github_installation_access_token_expires_at_timestamp = db.Column(db.Integer, index=True)

    # subscription(not used)
    premium_subscription = db.Column(db.Boolean, default=False)
    premium_until_timestamp = db.Column(db.Integer, index=True)

    # premium user
    is_premium = db.Column(db.Boolean, default=False)
    wants_premium = db.Column(db.Boolean, default=False)

    # model
    model_provider = db.Column(db.String(50)) # 'openai', 'groq', 'local'
    model_name = db.Column(db.String(50))

    # x token
    post_to_x_active = db.Column(db.Boolean, default=False)
    x_access_token_exists = db.Column(db.Boolean, default=False)
    x_access_token_encrypted = db.Column(db.String(120))
    x_refresh_token_encrypted = db.Column(db.String(120))
    x_access_token_expires_at_timestamp = db.Column(db.Integer, index=True)
    x_token_expires_at = db.Column(db.DateTime(timezone=True), nullable=True) # legacy
    x_username = db.Column(db.String(120), nullable=True)

    github_avatar_url = db.Column(db.String(200),nullable=True)
    posts = db.relationship('Post', backref='user')
    months = db.relationship('Month', backref='user')
    commits = db.relationship('Commit', backref='user')
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    settings = db.relationship('Settings', backref='user', uselist=False)
    notifications = db.relationship('Notification', backref='user')

    tracked_repos = db.relationship(
            'Repo', secondary=trackers,
            backref=db.backref('trackers', lazy='dynamic'))
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')


    @property
    def email_decrypted(self):
        return decrypt_item(self.email_encrypted)

    @email_decrypted.setter
    def email_decrypted(self, email):
        self.email_encrypted = encrypt_item(email)

    @property
    def github_installation_access_token_decrypted(self):
        return decrypt_item(self.github_installation_access_token_encrypted)

    @github_installation_access_token_decrypted.setter
    def github_installation_access_token_decrypted(self, token):
        self.github_installation_access_token_encrypted = encrypt_item(token)

    @property
    def github_user_access_token_decrypted(self):
        return decrypt_item(self.github_user_access_token_encrypted)

    @github_user_access_token_decrypted.setter
    def github_user_access_token_decrypted(self, token):
        self.github_user_access_token_encrypted = encrypt_item(token)

    @property
    def github_refresh_token_decrypted(self):
        return decrypt_item(self.github_refresh_token_encrypted)

    @github_refresh_token_decrypted.setter
    def github_refresh_token_decrypted(self, token):
        self.github_refresh_token_encrypted = encrypt_item(token)

    @property
    def x_access_token_decrypted(self):
        return decrypt_item(self.x_access_token_encrypted)

    @x_access_token_decrypted.setter
    def x_access_token_decrypted(self, token):
        self.x_access_token_encrypted = encrypt_item(token)

    @property
    def x_refresh_token_decrypted(self):
        return decrypt_item(self.x_refresh_token_encrypted)

    @x_refresh_token_decrypted.setter
    def x_refresh_token_decrypted(self, token):
        self.x_refresh_token_encrypted = encrypt_item(token)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0


    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return '<User %r' % self.name


def get_default_daily_summary_prompt():
    return "Your job is to summarize the changes made in the last 24 hours into a concise, 270-character summary for our customers. The summaries you are given are changes that have been made into the company's code repository in the last 24 hours and your job is to summarize these changes into informative update for the customers of the company so that they can see what value was created today. Make sure the output is not over 270 characters or I'll have to replace you."


class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    repo_id = db.Column(db.Integer, db.ForeignKey('repo.id'))
    # updates, posts
    feed_mode = db.Column(db.String(50), default='updates')
    private_public = db.Column(db.Boolean, default=False)

    markdown_widget_fill_color = db.Column(db.String(50), default='#232626')
    markdown_widget_stroke_color = db.Column(db.String(50), default='#0a8eb0')
    markdown_widget_text_color = db.Column(db.String(50), default='#ffffff')

    email = db.Column(db.String(150))
    email_notifications = db.Column(db.Boolean, default=False)

    automatic_new_repo_tracking = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<Settings %r' % self.id

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(50),default='user') # 'admin', 'user', 'report'
    message = db.Column(db.String(500))
    link = db.Column(db.String(500))
    seen = db.Column(db.Boolean, default=False)
    creation_timestamp = db.Column(db.Integer, index=True, nullable=False)

    def __repr__(self):
        return '<Notification %r' % self.id


class Month(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    summary = db.Column(db.String(500))
    comment = db.Column(db.String(500))

    creation_timestamp = db.Column(db.Integer, index=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Month %r' % self.id


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String)
    summarizing_style = db.Column(db.String(50), default='elaborate') # 'succinct', 'elaborate'
    not_finished = db.Column(db.Boolean, default=True)
    creation_timestamp = db.Column(db.Integer, index=True)
    lines_changed = db.Column(db.Integer, default=0)
    summary_token_count = db.Column(db.Integer, default=0)
    judging_token_count = db.Column(db.Integer, default=0)
    summary_provider = db.Column(db.String(50)) # 'openai', 'groq'
    summary_model = db.Column(db.String(50))
    x_posting_status = db.Column(db.String(50), default='pending')  # 'pending', 'success', 'failed'
    x_error_message = db.Column(db.Text)
    error_message = db.Column(db.Text)
    programming_language = db.Column(db.String(50))

    author_github_id = db.Column(db.String(300)) # in case user is not in the database
    author_github_login = db.Column(db.String(300)) # in case user is not in the database
    author_unknown = db.Column(db.Boolean, default=False) # legacy deleted
    unknown_author_name = db.Column(db.String(300)) # legacy deleted
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    repo_id = db.Column(db.Integer, db.ForeignKey('repo.id'))
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'))
    commits = db.relationship('Commit', backref='post')


    @property
    def content_decrypted(self):
        if self.repo.private:
            if self.content:
                return decrypt_item(self.content)
            return self.content
        else:
            return self.content

    @content_decrypted.setter
    def content_decrypted(self, token):
        if self.repo.private:
            if token:
                self.content = encrypt_item(token)
            else:
                self.content = token
        else:
            self.content = token

    def __repr__(self):
        return '<Post %r' % self.id

class Filetype(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    extension = db.Column(db.String(300))
    
    # flow goes like this:
    # when filetype comes in, 
    # if it is not in the database:
    #     -> if file ending in supported/unsupported list -> do accordingly and break
    #     -> analyzed beginning of the file to judge if it should be full_analyzis, never_analyze or beginning_analyze
    #     if it is beginning_analyze:
    #         -> it is analyzed only beginning like 10 lines to get the idea
    #         - analyze_beginning is set to True
    #     if it is full_analyze:
    #         -> it is analyzed fully
    #         - analyze_full is set to True
    #     if it is never_analyze:
    #         -> it is never analyzed
    #         - analyze_never is set to True
    #     if it is not any of the above:
    #         - should be made into an admin notification telling the problem ending type
    # else:
    #     if analyze_never is True:
    #         -> it is never analyzed
    #     else if analyze_full is True:
    #         -> it is analyzed fully
    #     else if analyze_beginning is True:
    #         -> it is analyzed only beginning like 10 lines to get the idea
    #     else:
    #         - should be made into an admin notification telling the problem ending type

    analyze_decision = db.Column(db.String(300)) # 'full', 'beginning', 'never', 'always_check'

    repo_id = db.Column(db.Integer, db.ForeignKey('repo.id'))

    def __repr__(self):
        return '<Filetype %r' % self.id

commit_association = db.Table(
    'commit_association',
    db.Column('parent_id', db.Integer, db.ForeignKey('commit.id')),
    db.Column('child_id', db.Integer, db.ForeignKey('commit.id'))
)

class Commit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sha = db.Column(db.String(300))
    message = db.Column(db.String(300))
    link = db.Column(db.String(300))
    creation_timestamp = db.Column(db.Integer, index=True)
    previous_branch_name = db.Column(db.String(300))
    author_github_login = db.Column(db.String(300))
    author_github_id = db.Column(db.String(300))
    author_unknown = db.Column(db.Boolean, default=False)
    unknown_author_name = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    branch_id = db.Column(db.Integer, db.ForeignKey('branch.id'))
    repo_id = db.Column(db.Integer, db.ForeignKey('repo.id'))
    parents = db.relationship(
        'Commit',
        secondary=commit_association,
        primaryjoin=id == commit_association.c.child_id,
        secondaryjoin=id == commit_association.c.parent_id,
        backref='children'
    )


    def __repr__(self):
        return '<Commit %r' % self.id


class Branch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300))
    repo_id = db.Column(db.Integer, db.ForeignKey('repo.id'))
    main_branch = db.Column(db.Boolean, default=False)
    dev_branch = db.Column(db.Boolean, default=False)
    hot_fix = db.Column(db.Boolean, default=False)
    latest_commit_sha = db.Column(db.String(300))
    posts = db.relationship('Post', backref='branch')
    commits = db.relationship('Commit', backref='branch')

    def __repr__(self):
        return '<Branch %r' % self.id

class Repo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    github_id = db.Column(db.String(300))
    name = db.Column(db.String(300))
    repo_description = db.Column(db.String(150))
    owner_github_login = db.Column(db.String(300))
    owner_github_id = db.Column(db.String(300))
    webhook_id = db.Column(db.Integer)
    webhook_active = db.Column(db.Boolean, default=False)
    added_timestamp = db.Column(db.Integer, index=True)
    last_push_timestamp = db.Column(db.Integer, index=True)
    preferred_language = db.Column(db.String(300), default='english')
    main_branch_in_use = db.Column(db.Boolean, default=True)
    main_branch_name = db.Column(db.String(300), default="master")
    main_branch_hex_color = db.Column(db.String(50), default="#4FADB7")
    dev_branch_in_use = db.Column(db.Boolean, default=True)
    dev_branch_name = db.Column(db.String(300), default="dev")
    dev_branch_hex_color = db.Column(db.String(50), default="#C2CC20")
    hotfix_branch_in_use = db.Column(db.Boolean, default=True)
    hotfix_branch_contains_name = db.Column(db.String(300), default="hotfix")
    hotfix_branch_hex_color = db.Column(db.String(50), default="#f44336")

    # x token
    post_to_x_active = db.Column(db.Boolean, default=False)
    posting_interval = db.Column(db.String(50), default='daily') # 'instant', 'daily' 
    posting_hour = db.Column(db.Integer, default=0)
    x_access_token_exists = db.Column(db.Boolean, default=False)
    x_access_token_encrypted = db.Column(db.String(120))
    x_refresh_token_encrypted = db.Column(db.String(120))
    x_access_token_expires_at_timestamp = db.Column(db.Integer, index=True)
    x_username = db.Column(db.String(120), nullable=True)

    settings = db.relationship('Settings', backref='repo', uselist=False)
    posts = db.relationship('Post', backref='repo')
    branches = db.relationship('Branch', backref='repo')
    commits = db.relationship('Commit', backref='repo')
    filetypes = db.relationship('Filetype', backref='repo')
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    private = db.Column(db.Boolean, default=False, nullable=False)
    allow_public_posting = db.Column(db.Boolean, default=False)
    members = db.relationship(
        'User',
        secondary=trackers,
        back_populates='tracked_repos'
    )

    @property
    def x_access_token_decrypted(self):
        return decrypt_item(self.x_access_token_encrypted)

    @x_access_token_decrypted.setter
    def x_access_token_decrypted(self, token):
        self.x_access_token_encrypted = encrypt_item(token)

    @property
    def x_refresh_token_decrypted(self):
        return decrypt_item(self.x_refresh_token_encrypted)

    @x_refresh_token_decrypted.setter
    def x_refresh_token_decrypted(self, token):
        self.x_refresh_token_encrypted = encrypt_item(token)


    def __repr__(self):
        return '<Repo %r' % self.id

class UserRepoLastSeen(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    repo_id = db.Column(db.Integer, db.ForeignKey('repo.id'))
    last_seen_post_id = db.Column(db.Integer, db.ForeignKey('post.id'))

class Payload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content_json_str = db.Column(db.String)
    creation_timestamp = db.Column(db.Integer, index=True)
    status = db.Column(db.String(50), default='pending') # 'pending', 'success', 'failed'

    # setters getters for json dumbs loads
    @property
    def content(self):
        return json.loads(self.content_json_str)

    @content.setter
    def content(self, content):
        self.content_json_str = json.dumps(content)

    def __repr__(self):
        return '<Payload %r' % self.id
