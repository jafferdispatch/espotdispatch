import random
import string
from flask import Blueprint, request, jsonify, session, make_response
from flask_mail import Message
from flask_login import login_user
from models import db, Admin, TrustedDevice  # Ensure you have a TrustedDevice model

api_auth_bp = Blueprint('api_auth', __name__, url_prefix='/api')

# OTP Storage (Ideally, store in a database for production)
otp_storage = {}

def generate_otp():
    """ Generate a 6-digit OTP """
    return ''.join(random.choices(string.digits, k=6))

@api_auth_bp.route('/check-device', methods=['POST'])
def check_device():
    """ Check if a device is trusted for the given user """
    data = request.json
    username = data.get("username")
    device_id = data.get("device_id")

    admin = Admin.query.filter_by(username=username).first()
    if not admin:
        return jsonify({"error": "User not found"}), 404

    # Check if the device is already trusted
    trusted = TrustedDevice.query.filter_by(admin_id=admin.id, device_id=device_id).first()
    return jsonify({"trusted": bool(trusted)}), 200

@api_auth_bp.route('/send-2fa', methods=['POST'])
def send_2fa():
    """ Send OTP to the admin's email """
    data = request.json
    username = data.get("username")

    admin = Admin.query.filter_by(username=username).first()
    if not admin:
        return jsonify({"error": "User not found"}), 404

    # Generate OTP and store it temporarily
    otp_code = generate_otp()
    otp_storage[username] = otp_code

    # Send email
    msg = Message('Your 2FA Code', recipients=[admin.email])
    msg.body = f"Your 2FA code is: {otp_code}"
    try:
        mail.send(msg)
        return jsonify({"message": "2FA code sent"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_auth_bp.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    """ Verify the OTP entered by the user """
    data = request.json
    username = data.get("username")
    otp_code = data.get("otp_code")
    device_id = data.get("device_id")

    admin = Admin.query.filter_by(username=username).first()
    if not admin:
        return jsonify({"error": "User not found"}), 404

    # Check OTP
    if otp_storage.get(username) == otp_code:
        otp_storage.pop(username)  # Remove OTP after successful verification
        login_user(admin)  # Log the user in

        response = make_response(jsonify({"message": "2FA verified"}), 200)
        response.set_cookie('device_id', device_id, httponly=True, max_age=60 * 60 * 24 * 30)  # 30 days
        return response
    else:
        return jsonify({"error": "Invalid OTP"}), 400

@api_auth_bp.route('/remember-device', methods=['POST'])
def remember_device():
    """ Mark a device as trusted """
    data = request.json
    username = data.get("username")
    device_id = data.get("device_id")

    admin = Admin.query.filter_by(username=username).first()
    if not admin:
        return jsonify({"error": "User not found"}), 404

    # Add device to trusted list if not already stored
    if not TrustedDevice.query.filter_by(admin_id=admin.id, device_id=device_id).first():
        new_device = TrustedDevice(admin_id=admin.id, device_id=device_id)
        db.session.add(new_device)
        db.session.commit()

    return jsonify({"message": "Device remembered"}), 200
