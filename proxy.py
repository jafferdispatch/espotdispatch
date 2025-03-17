import random
import string

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from uuid import uuid4

from flask_login import login_required
import jwt
import os
from functools import wraps
from models import db, Proxy, User, Group, Session, Content, TrustedDevice
from datetime import timedelta
import datetime
from werkzeug.security import check_password_hash
from flask_mail import Message
from auth import mail

# OTP Storage (Temporary dictionary for development)
otp_storage = {}

proxies_bp = Blueprint('proxy', __name__, url_prefix='/proxies')

SESSION_TIMEOUT = timedelta(seconds=90)

# List all proxies
@proxies_bp.route('/', methods=['GET'])
@login_required
def index():
    proxies = Proxy.query.all()
    for proxy in proxies:
        print(proxy.assigned_to_users)

    return render_template('proxies/index.html', proxies=proxies, page='proxies')


# Add a new proxy
@proxies_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_proxy():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        host = request.form['host']
        port = request.form['port']

        # Validate input
        if not username or not password or not host or not port:
            flash('All fields are required!', 'danger')
            return redirect(url_for('proxy.add_proxy'))

        # # Check for unique constraints
        # if Proxy.query.filter((Proxy.username == username) | (Proxy.host == host) | (Proxy.port == port)).first():
        #     flash('Proxy details must be unique!', 'danger')
        #     return redirect(url_for('proxy.add_proxy'))

        # Create a new proxy
        new_proxy = Proxy(
            id=uuid4().hex,
            username=username,
            password=password,
            host=host,
            port=port,
        )
        db.session.add(new_proxy)
        db.session.commit()

        flash('Proxy added successfully!', 'success')
        return redirect(url_for('proxy.index'))
    return render_template('proxies/add_proxy.html', page='proxies')

@proxies_bp.route('/edit/<proxy_id>', methods=['GET', 'POST'])
@login_required
def edit_proxy(proxy_id):
    proxy = Proxy.query.get_or_404(proxy_id)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        host = request.form.get('host')
        port = request.form.get('port')

        # Validate input
        if not username or not host or not port:
            flash('All fields are required!', 'danger')
            return redirect(url_for('proxy.edit_proxy', proxy_id=proxy_id))

        # Check for unique constraints (excluding the current proxy being edited)
        # existing_proxy = Proxy.query.filter(
        #     ((Proxy.username == username) |
        #      (Proxy.host == host) |
        #      (Proxy.port == port)) &
        #     (Proxy.id != proxy_id)
        # ).first()
        #
        # if existing_proxy:
        #     flash('Proxy details must be unique!', 'danger')
        #     return redirect(url_for('proxy.edit_proxy', proxy_id=proxy_id))

        # Update proxy details
        proxy.username = username
        if password:
            proxy.password = password
        proxy.host = host
        proxy.port = port

        db.session.commit()

        flash('Proxy updated successfully!', 'success')
        return redirect(url_for('proxy.index'))

    return render_template('proxies/edit_proxy.html', proxy=proxy, page='proxies')


@proxies_bp.route('/delete/<proxy_id>', methods=['POST'])
@login_required
def delete_proxy(proxy_id):
    proxy = Proxy.query.get_or_404(proxy_id)

    try:
        db.session.delete(proxy)
        db.session.commit()
        flash('Proxy deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting proxy: {e}', 'danger')

    return redirect(url_for('proxy.index'))


@proxies_bp.route('/assign', methods=['GET', 'POST'])
@login_required
def assign_proxy():
    if request.method == 'POST':
        data = request.get_json()
        proxy_id = data.get('proxy_id')
        user_ids = data.get('user_ids', [])

        if not proxy_id or not user_ids:
            return jsonify(success=False, message="Invalid input")

        proxy = Proxy.query.get(proxy_id)
        if not proxy:
            return jsonify(success=False, message="Proxy not found")

        users = User.query.filter(User.id.in_(user_ids)).all()
        for user in users:
            user.proxy_id = proxy_id

        db.session.commit()
        return jsonify(success=True)

    users = User.query.all()
    proxies = Proxy.query.all()
    return render_template(
        'proxies/assign_proxy.html', users=users, proxies=proxies, page='assign_proxies'
    )


@proxies_bp.route('/assign-to-group', methods=['GET', 'POST'])
@login_required
def assign_proxy_group():
    if request.method == 'POST':
        data = request.get_json()
        proxy_id = data.get('proxy_id')
        group_id = data.get('group_id')

        if not proxy_id or not group_id:
            return jsonify(success=False, message="Invalid input")

        group = Group.query.get(group_id)
        if not group:
            return jsonify(success=False, message="Group not found")

        proxy = Proxy.query.get(proxy_id)
        if not proxy:
            return jsonify(success=False, message="Proxy not found")

        # Overwrite any existing assignment
        for user in group.users:
            user.proxy_id = proxy_id

        db.session.commit()
        return jsonify(success=True)

    groups = Group.query.all()
    proxies = Proxy.query.all()
    return render_template(
        'proxies/assign_proxy_group.html', groups=groups, proxies=proxies, page='assign_proxies_group'
    )



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



def generate_otp():
    """ Generate a 6-digit OTP """
    return ''.join(random.choices(string.digits, k=6))

@proxies_bp.route('/send-2fa', methods=['POST'])
def send_2fa():
    """ Send OTP to the user's email """
    data = request.json
    username = data.get("username")
    user = User.query.filter_by(username=username).first()
    print(f'Sending email to username: {username} with email')
    if not user:
        return jsonify({"status": 0, "error_message": "User not found"}), 404

    # Generate OTP and store it temporarily
    otp_code = generate_otp()
    otp_storage[username] = otp_code

    # Send email
    msg = Message('Your 2FA Code', recipients=[user.email])
    msg.body = f"Your 2FA code is: {otp_code}"
    try:
        mail.send(msg)
        return jsonify({"status": 1, "message": "2FA code sent"}), 200
    except Exception as e:
        return jsonify({"status": 0, "error_message": str(e)}), 500

@proxies_bp.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    """ Verify the OTP entered by the user """
    data = request.json
    username = data.get("username")
    otp_code = data.get("otp_code")
    device_id = data.get("device_id")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"status": 0, "error_message": "User not found"}), 200

    # Check OTP
    if otp_storage.get(username) == otp_code:
        otp_storage.pop(username)  # Remove OTP after successful verification

        # Mark device as trusted
        if not TrustedDevice.query.filter_by(user_id=user.id, device_id=device_id).first():
            new_device = TrustedDevice(user_id=user.id, device_id=device_id)
            db.session.add(new_device)
            db.session.commit()

        return jsonify({"status": 1, "message": "2FA verified"}), 200
    else:
        return jsonify({"status": 0, "error_message": "Invalid OTP"}), 200


@proxies_bp.route('/get-proxy', methods=['POST'])
def get_proxy():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    device_id = data.get("device_id")  # New: Device ID for trusted devices

    if not username or not password:
        return jsonify({'status': 0, 'error_message': 'Username and password are required'}), 200

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'status': 0, 'error_message': 'Username not found'}), 200

    if not check_password_hash(user.password, password):
        return jsonify({'status': 0, 'error_message': 'Incorrect password'}), 200

    if user.disabled or (user.disabled_after and datetime.datetime.now() > user.disabled_after):
        return jsonify({'status': 0, 'error_message': 'User Expired. Please Contact Espot Solutions.'}), 200

    requires_2fa = False
    if user.two_factor:
        # 2FA Check: If the device is not trusted, request 2FA
        trusted_device = TrustedDevice.query.filter_by(user_id=user.id, device_id=device_id).first()
        if not trusted_device:
            requires_2fa = True  # Frontend should trigger 2FA request


    content = Content.query.filter_by(user_id=user.id).first()
    if not content:
        return jsonify({'status': 0, 'error_message': 'No content found for this user.'}), 200

    if not user.proxy_id:
        return jsonify({'status': 0, 'error_message': content.unassigned_proxy_error_dialog if content.unassigned_proxy_error_dialog else 'Your account configuration is incomplete. Contact support'}), 200

    proxy = Proxy.query.get(user.proxy_id)
    if not proxy:
        return jsonify({'status': 0, 'error_message': content.unassigned_proxy_error_dialog if content.unassigned_proxy_error_dialog else 'Your account configuration is incomplete. Contact support'}), 200

    # Remove expired sessions
    expired_sessions = Session.query.filter_by(user_id=user.id).filter(Session.last_seen < datetime.datetime.now() - SESSION_TIMEOUT).all()
    for session in expired_sessions:
        db.session.delete(session)
    db.session.commit()

    # Check active session limit
    active_sessions = Session.query.filter_by(user_id=user.id).count()
    if active_sessions >= user.session_limit:
        return jsonify({'status': 0, 'error_message': 'Session limit reached. Please close other sessions and try again in a minute.'}), 200

    # Create a new session for the user
    ip_address = request.remote_addr
    new_session = Session(user_id=user.id, ip_address=ip_address)
    db.session.add(new_session)
    db.session.commit()

    proxy_details = {
        'proxy_url': proxy.host,
        'proxy_port': proxy.port,
        'proxy_user': proxy.username,
        'proxy_password': proxy.password,
        'disabled_after': user.disabled_after,
        'sync_data': user.sync_data
    }

    content_details = {
        'logo_url': content.logo_url,
        'phone_number': content.phone_number,
        'default_url': content.default_url,
        'closing_dialog': content.closing_dialog,
    }

    return jsonify({'status': 1, 'proxy_details': proxy_details, 'content_details': content_details, 'message': 'Login successful', 'requires_2fa': requires_2fa, 'email': user.email}), 200


@proxies_bp.route('/get-content', methods=['POST'])
def get_content():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 0, 'error_message': 'Username and password are required'}), 200

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'status': 0, 'error_message': 'Username not found'}), 200

    if not check_password_hash(user.password, password):
        return jsonify({'status': 0, 'error_message': 'Incorrect password'}), 200

    if user.disabled or (user.disabled_after and datetime.datetime.now() > user.disabled_after):
        return jsonify({'status': 0, 'error_message': 'User Expired. Please Contact Support.'}), 200

    # Fetch content associated with the user
    content = Content.query.filter_by(user_id=user.id).first()
    if not content:
        return jsonify({'status': 0, 'error_message': 'No content found for this user.'}), 200

    content_details = {
        'logo_url': content.logo_url,
        'phone_number': content.phone_number,
        'default_url': content.default_url
    }

    return jsonify({'status': 1, 'content_details': content_details, 'message': 'Content retrieval successful'}), 200


@proxies_bp.route('/remember-device', methods=['POST'])
def remember_device():
    """ Mark a device as trusted """
    data = request.json
    username = data.get("username")
    device_id = data.get("device_id")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Add device to trusted list if not already stored
    if not TrustedDevice.query.filter_by(user_id=user.id, device_id=device_id).first():
        new_device = TrustedDevice(user_id=user.id, device_id=device_id)
        db.session.add(new_device)
        db.session.commit()

    return jsonify({"message": "Device remembered"}), 200

@proxies_bp.route('/check-device', methods=['POST'])
def check_device():
    """ Check if a device is trusted for the given user """
    data = request.json
    username = data.get("username")
    device_id = data.get("device_id")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check if the device is already trusted
    trusted = TrustedDevice.query.filter_by(user_id=user.id, device_id=device_id).first()
    return jsonify({"trusted": bool(trusted)}), 200
