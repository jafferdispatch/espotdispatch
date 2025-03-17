from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required

from models import db, User, Proxy, Content
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

users_bp = Blueprint('users', __name__, url_prefix='/users')


# View all users
@users_bp.route('/')
@login_required
def index():
    search_query = request.args.get('search', '')

    if search_query:
        users = User.query.filter(
            User.username.ilike(f'%{search_query}%'),
            User.group_id == None
        ).order_by(User.username.asc()).all()
    else:
        users = User.query.filter(
            User.group_id == None
        ).order_by(User.username.asc()).all()

    for user in users:
        # print(user.disabled_after, datetime.now())
        if user.disabled_after and user.disabled_after <= datetime.now():
            user.disabled = True
    db.session.commit()

    proxies = Proxy.query.all()
    return render_template(
        'users/index.html',
        users=users,
        search_query=search_query,
        page='users',
        proxies=proxies
    )


@users_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        disabled_after_str = request.form['disabled_after']

        # Validate input
        if not username or not email or not password or not disabled_after_str:
            flash('All fields are required!', 'danger')
            return redirect(url_for('users.add_user'))

        user = User.query.filter_by(username=username).first()
        if user:
            flash('User with this username already exists.', 'danger')
            return redirect(url_for('users.add_user'))
        user = User.query.filter_by(email=email).first()
        if user:
            flash('User with this email already exists.', 'danger')
            return redirect(url_for('users.add_user'))

        try:
            # Convert the disabled_after string to a datetime object
            disabled_after = datetime.strptime(disabled_after_str, "%Y-%m-%dT%H:%M")
        except ValueError:
            flash('Invalid date and time format!', 'danger')
            return redirect(url_for('users.add_user'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            disabled_after=disabled_after
        )
        db.session.add(new_user)
        db.session.commit()

        # Add default content for the new user
        default_content = Content(
            logo_url='image_url',
            phone_number='03204342479',
            default_url='https://espotsolutions.com/',
            closing_dialog='Closing, please wait.',
            unassigned_proxy_error_dialog='Your account configuration is incomplete. Contact support.',
            user_id=new_user.id
        )
        db.session.add(default_content)
        db.session.commit()

        flash('User added successfully!', 'success')
        return redirect(url_for('users.index'))

    return render_template('users/add_user.html', page='users')


# Edit user details
@users_bp.route('/edit/<string:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        check_user = User.query.filter_by(username=username).first()
        if check_user:
            if not check_user.username == user.username:
                flash('User with this username already exists.', 'danger')
                return redirect(url_for('users.edit_user', user_id=user_id))

        check_user = User.query.filter_by(email=email).first()
        if check_user:
            if not check_user.email == user.email:
                flash('User with this email already exists.', 'danger')
                return redirect(url_for('users.edit_user', user_id=user_id))

        user.username = username
        user.email = email

        # Handle password update
        new_password = request.form.get('password')
        if new_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')

        db.session.commit()

        flash('User updated successfully!', 'success')

        if not user.group_id:
            return redirect(url_for('users.index'))
        return redirect(url_for('groups.group_users', group_id=user.group_id))
    return render_template('users/edit_user.html', user=user, page='users')


# Delete a user
@users_bp.route('/delete/<string:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    user_group_id = user.group_id
    db.session.delete(user)
    db.session.commit()

    flash('User deleted successfully!', 'success')

    if not user.group_id:
        return redirect(url_for('users.index'))

    return redirect(url_for('groups.group_users', group_id=user.group_id))


@users_bp.route('/suspend_user', methods=['POST'])
@login_required
def suspend_user():
    user_id = request.json.get('user_id')
    # Logic to suspend user
    user = User.query.get(user_id)
    if user:
        user.disabled = True
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False)


@users_bp.route('/extend_user', methods=['POST'])
@login_required
def extend_user():
    data = request.json
    user_id = data.get('user_id')
    disabled_after = data.get('disabled_after')
    # Logic to extend user activity
    user = User.query.get(user_id)
    if user:
        user.disabled_after = datetime.fromisoformat(disabled_after)
        user.disabled = False
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False)

@users_bp.route('/proxies', methods=['GET'])
@login_required
def get_proxies():
    user_id = request.args.get('user_id')
    # Fetch all proxies (modify as needed for filtering logic)
    proxies = Proxy.query.all()
    return jsonify([{"id": proxy.id, "host": proxy.host} for proxy in proxies])

@users_bp.route('/assign_proxy', methods=['POST'])
@login_required
def assign_proxy():
    data = request.json
    user_id = data['user_id']
    proxy_id = data['proxy_id']

    user = User.query.get(user_id)
    proxy = Proxy.query.get(proxy_id)

    if user and proxy:
        user.proxy = proxy
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False)

@users_bp.route('/toggle_sync', methods=['POST'])
@login_required
def toggle_sync():
    user_id = request.json.get('user_id')

    if not user_id:
        return jsonify({'success': False, 'message': 'Invalid user ID'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Toggle sync status
    user.sync_data = not user.sync_data
    db.session.commit()

    return jsonify({'success': True, 'sync_data': user.sync_data, 'message': f'Sync turned {"on" if user.sync_data else "off"}'})

@users_bp.route("/update-session-limit", methods=["POST"])
def update_session_limit():
    user_id = request.form.get("user_id")
    session_limit = request.form.get("session_limit")

    if not user_id or not session_limit:
        return jsonify({"success": False, "message": "Invalid input"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    try:
        user.session_limit = int(session_limit)
        db.session.commit()
        return jsonify({"success": True, "message": "Session limit updated successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


@users_bp.route('/<string:user_id>/remove_proxy', methods=['POST'])
@login_required
def remove_proxy(user_id):
    user = User.query.get_or_404(user_id)

    if user.proxy_id:
        user.proxy_id = None  # Unassign proxy
        db.session.commit()
        flash("Proxy removed successfully.", "success")
    else:
        flash("User has no assigned proxy.", "warning")

    return redirect(url_for('users.index'))  # Adjust the redirect as needed


@users_bp.route('/toggle_2fa', methods=['POST'])
@login_required
def toggle_2fa():
    user_id = request.json.get('user_id')

    if not user_id:
        return jsonify({'success': False, 'message': 'Invalid user ID'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Toggle sync status
    user.two_factor = not user.two_factor
    db.session.commit()

    return jsonify({'success': True, 'two_factor': user.two_factor, 'message': f'Two factor turned {"on" if user.two_factor else "off"}'})
