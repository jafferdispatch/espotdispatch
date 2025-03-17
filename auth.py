import os
import random
import string

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, make_response
from flask_login import login_user, logout_user, current_user, login_required
from models import db, Admin
from werkzeug.security import generate_password_hash
from flask_mail import Mail, Message

auth_bp = Blueprint('auth', __name__)

# Mail configuration
mail = Mail()

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # admins = Admin.query.all()
    # for admin in admins:
    #     db.session.delete(admin)
    #     db.session.commit()
    # password = generate_password_hash('Pakistan@6656!!', method='pbkdf2:sha256')
    # new_admin = Admin(username='m.ghaffar', email='ghaffardar382@gmail.com', password=password)
    # db.session.add(new_admin)
    # db.session.commit()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()

        if admin and admin.verify_password(password):
            # Generate a unique identifier for the device
            device_id = request.cookies.get('device_id')
            if not device_id:
                device_id = ''.join(random.choices(string.ascii_letters + string.digits, k=32))

            # Check if this device has been verified before
            if not admin.is_device_verified(device_id):  # Custom method in Admin model
                otp = generate_otp()
                session['2fa_otp'] = otp
                session['pending_admin'] = admin.id
                flash('A verification code has been sent to your email.', 'info')

                # Send email
                msg = Message('Your 2FA Code', recipients=[admin.email])
                msg.body = f"Your 2FA code is: {otp}"
                mail.send(msg)

                return redirect(url_for('auth.verify_2fa'))

            login_user(admin)
            flash('Logged in successfully!', 'success')

            # Mark device as trusted (set cookie)
            response = make_response(redirect(url_for('index')))
            response.set_cookie('device_id', device_id, httponly=True, max_age=60 * 60 * 24 * 30)  # 30 days

            return response

        flash('Invalid credentials', 'danger')

    return render_template('auth/login.html')


@auth_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_admin' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('2fa_otp'):
            admin = Admin.query.get(session['pending_admin'])
            if admin:
                device_id = request.cookies.get('device_id',
                                                ''.join(random.choices(string.ascii_letters + string.digits, k=32)))
                admin.mark_device_verified(device_id)  # Store verified device
                db.session.commit()

                login_user(admin)
                flash('2FA verification successful!', 'success')

                # Set trusted device cookie
                response = make_response(redirect(url_for('index')))
                response.set_cookie('device_id', device_id, httponly=True, max_age=60 * 60 * 24 * 30)

                session.pop('2fa_otp', None)
                session.pop('pending_admin', None)

                return response

        flash('Invalid OTP, try again.', 'danger')

    return render_template('auth/verify_2fa.html')
#
# @auth_bp.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         email = request.form['email']
#         password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
#
#         if Admin.query.filter_by(email=email).first():
#             flash('Email already exists!', 'danger')
#             return redirect(url_for('auth.signup'))
#
#         new_admin = Admin(username=username, email=email, password=password)
#         db.session.add(new_admin)
#         db.session.commit()
#
#         flash('Admin account created successfully!', 'success')
#         return redirect(url_for('auth.login'))
#
#     return render_template('auth/signup.html')

@auth_bp.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('auth.login'))
