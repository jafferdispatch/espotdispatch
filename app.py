from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from datetime import datetime
import jwt
from models import db, User, Proxy, Admin, Session, LoginPageContent
from flask_login import LoginManager, login_required
from dotenv import load_dotenv
import os
from flask_migrate import Migrate
from functools import wraps
from auth import auth_bp, mail
from users import users_bp
from proxy import proxies_bp
from groups import groups_bp
from cookie import cookie_api
from content import content_bp

app = Flask(__name__)

load_dotenv()

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db.init_app(app)
migrate = Migrate(app, db)

with app.app_context():
    # db.session.execute(text('SET session_replication_role = replica;'))  # PostgreSQL
    # db.drop_all()
    db.create_all()
    # db.session.execute('SET session_replication_role = DEFAULT;')  # PostgreSQL


login_manager = LoginManager(app)

# Configure LoginManager
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(admin_id):
    return Admin.query.get(admin_id)


# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(users_bp, url_prefix='/users')
app.register_blueprint(proxies_bp, url_prefix='/proxy')
app.register_blueprint(groups_bp, url_prefix='/groups')
app.register_blueprint(cookie_api, url_prefix='/')
app.register_blueprint(content_bp, url_prefix='/content')

app.config['DEBUG'] = True  # Add this line
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail.init_app(app)

@app.route('/')
@login_required
def index():
    num_users = User.query.count()
    num_proxies = Proxy.query.count()
    return render_template('dashboard.html', num_users=num_users, num_proxies=num_proxies, page='dashboard')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'status': 0, 'error_message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, os.getenv('TOKEN_SECRET_KEY'), algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 0, 'error_message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'status': 0, 'error_message': 'Invalid token!'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/heartbeat', methods=['POST'])
# @token_required
def heartbeat():
    data = request.json
    username = data.get('username')
    login_status = data.get('status')
    ip_address = request.remote_addr

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    # Check the number of active sessions for the user
    active_sessions = Session.query.filter_by(user_id=user.id).count()
    try:
        if login_status is False:
            # Remove the session for the given IP address
            session = Session.query.filter_by(user_id=user.id, ip_address=ip_address).first()
            if session:
                db.session.delete(session)
        else:
            # Check if the user has reached the session limit
            if active_sessions > user.session_limit:
                return jsonify({'status': 'error', 'message': 'Session limit reached'}), 403

            # Update or create the session for the given IP address
            session = Session.query.filter_by(user_id=user.id, ip_address=ip_address).first()
            if session:
                session.last_seen = datetime.now()
            else:
                new_session = Session(user_id=user.id, ip_address=ip_address)
                db.session.add(new_session)
        db.session.commit()
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        print(e)
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500



@app.route('/get-login-page-content', methods=['GET'])
def get_login_page_content():
    content = LoginPageContent.query.first()

    if not content:
        content = LoginPageContent()
        db.session.add(content)
        db.session.commit()
        # return jsonify({'status': 0, 'error_message': 'No content found.'}), 404

    content_details = {
        'logo_url': content.logo_url,
        'phone_number': content.phone_number,
        'slogan': content.slogan,
        'contact_line': content.contact_line
    }

    return jsonify({'status': 1, 'content_details': content_details}), 200



# Generic error handler for all exceptions
@app.errorhandler(500)
def handle_exception(e):
    # Log the exception details
    print(f"Unhandled Exception: {e}")

    # Flash a generic error message
    flash("An unexpected error occurred. Please contact support if this continues.", "danger")

    # Redirect to a safe page (e.g., home page)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
