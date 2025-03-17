import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Admin(UserMixin, db.Model):
    id = db.Column(db.String(64), primary_key=True, default=lambda: uuid4().hex)
    username = db.Column(db.String(256), unique=True, nullable=False)
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    verified_devices = db.Column(db.Text, default="")  # Store verified device IDs

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def is_device_verified(self, device_id):
        if not self.verified_devices:
            return None
        return device_id in self.verified_devices.split(',')

    def mark_device_verified(self, device_id):
        if not self.is_device_verified(device_id):
            if self.verified_devices:
                self.verified_devices += f",{device_id}"
            else:
                self.verified_devices = device_id

class User(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: uuid4().hex)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    disabled_after = db.Column(db.DateTime, nullable=True)
    disabled = db.Column(db.Boolean, nullable=False, default=False)
    session_limit = db.Column(db.Integer, nullable=False, default=1)
    proxy_id = db.Column(db.String(64), db.ForeignKey('proxy.id'), nullable=True)
    proxy = db.relationship('Proxy', back_populates='assigned_to_users')  # Relationship with Proxy
    group_id = db.Column(db.String(32), db.ForeignKey('group.id'), nullable=True) 
    group = db.relationship('Group', back_populates='users')  # Relationship with Group
    sync_data = db.Column(db.Boolean, nullable=True, default=False)
    two_factor = db.Column(db.Boolean, nullable=True, default=False)

    contents = db.relationship('Content', backref='user', cascade="all, delete", passive_deletes=True)

    sessions = db.relationship('Session', backref='user', cascade="all, delete", passive_deletes=True)

    def set_disabled_after(self, days, hours):
        """Set the disabled_after time based on days and hours"""
        self.disabled_after = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=days, hours=hours)
        db.session.commit()

    def get_proxy_hostname(self):
        proxy = Proxy.query.filter_by(id=self.proxy_id).first()
        if proxy:
            return proxy.host
        return None

    def __repr__(self):
        return self.username
    
class TrustedDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), db.ForeignKey('user.id'), nullable=False)
    device_id = db.Column(db.String(200), nullable=False, unique=True)

class Proxy(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: uuid4().hex)  # 32-character UUID
    username = db.Column(db.String(256), nullable=False)
    password = db.Column(db.Text, nullable=False)
    host = db.Column(db.String(256), nullable=False)
    port = db.Column(db.String(16), nullable=False)
    
    assigned_to_users = db.relationship('User', back_populates='proxy')


class Content(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: uuid4().hex)  # 32-character UUID
    logo_url = db.Column(db.Text, nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    default_url = db.Column(db.String(255), nullable=True)
    closing_dialog = db.Column(db.Text, nullable=True)
    unassigned_proxy_error_dialog = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.String(32), db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)

    def to_dict(self):
        return {
            "logo_url": self.logo_url,
            "phone_number": self.phone_number,
            "default_url": self.default_url,
            "user_id": self.user_id,
            "closing_dialog": self.closing_dialog,
            "unassigned_proxy_error_dialog": self.unassigned_proxy_error_dialog
        }


class LoginPageContent(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: uuid4().hex)  # 32-character UUID
    logo_url = db.Column(db.Text, nullable=True, default='https://espotbrowser.onrender.com/static/images/logo.png')
    phone_number = db.Column(db.String(20), nullable=True, default='03204342479')
    slogan = db.Column(db.Text, nullable=True, default='Your Gateway to Business Excellence')
    contact_line = db.Column(db.Text, nullable=True, default='In case of issues, contact Espot Solutions at:')

    def to_dict(self):
        return {
            "logo_url": self.logo_url,
            "phone_number": self.phone_number,
            "slogan": self.slogan,
            "contact_line": self.contact_line,
        }

class Group(db.Model):
    id = db.Column(db.String(32), primary_key=True, default=lambda: uuid4().hex)
    name = db.Column(db.String(100), unique=True, nullable=False)

    users = db.relationship('User', back_populates='group', cascade="all, delete-orphan")


class Cookie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    cookies = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(datetime.UTC))

    def __init__(self, username, cookies):
        self.username = username
        self.cookies = cookies

class Session(db.Model):
    id = db.Column(db.String(64), primary_key=True, default=lambda: uuid4().hex)
    user_id = db.Column(db.String(32), db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    # user = db.relationship('User', backref='sessions', cascade="all, delete", passive_deletes=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(datetime.UTC))
    last_seen = db.Column(db.DateTime, default=datetime.datetime.now(datetime.UTC))
    ip_address = db.Column(db.String(64), nullable=False)

    def __repr__(self):
        return f"Session({self.user_id}, {self.ip_address})"