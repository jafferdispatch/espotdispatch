from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash
from uuid import uuid4

from flask_login import login_required

from models import db, Group, User
from werkzeug.security import generate_password_hash

groups_bp = Blueprint('groups', __name__, url_prefix='/groups')

# Add a new group
@groups_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_group():
    if request.method == 'POST':
        name = request.form['name']

        # Validate input
        if not name:
            flash('Group name is required!', 'danger')
            return redirect(url_for('groups.add_group'))

        if Group.query.filter_by(name=name).first():
            flash('Group already exists!', 'danger')
            return redirect(url_for('groups.add_group'))

        new_group = Group(id=uuid4().hex, name=name)
        db.session.add(new_group)
        db.session.commit()

        flash('Group added successfully!', 'success')
        return redirect(url_for('groups.list_groups'))
    
    return render_template('groups/add_group.html', page='groups')

# List all groups
@groups_bp.route('/', methods=['GET'])
@login_required
def list_groups():
    groups = Group.query.all()
    return render_template('groups/index.html', groups=groups, page='groups')

# View users in a group
@groups_bp.route('/<group_id>/users', methods=['GET'])
@login_required
def group_users(group_id):
    group = Group.query.get_or_404(group_id)

    for user in group.users:
        if user.disabled_after and user.disabled_after <= datetime.now():
            user.disabled = True
    db.session.commit()

    return render_template('groups/group_users.html', group=group, page='groups')


@groups_bp.route('/group/<group_id>/add_user', methods=['GET', 'POST'])
@login_required
def add_user_to_group(group_id):
    group = Group.query.get_or_404(group_id)
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        disabled_after_str = request.form['disabled_after']

        # Parse the 'disabled_after' datetime-local input
        try:
            disabled_after = datetime.fromisoformat(disabled_after_str)
        except ValueError:
            flash('Invalid date format for Active Until!', 'danger')
            return redirect(url_for('groups.add_user_to_group', group_id=group.id))

        # Create new user with the provided details
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            disabled_after=disabled_after
        )

        # Check if the user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists', 'danger')
            return redirect(url_for('groups.add_user_to_group', group_id=group.id))
        
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash('User with this username already exists', 'danger')
            return redirect(url_for('groups.add_user_to_group', group_id=group.id))

        # Add user to the group
        new_user.group = group
        db.session.add(new_user)
        db.session.commit()

        flash('User added to the group successfully!', 'success')
        return redirect(url_for('groups.group_users', group_id=group.id))

    # Fetch users who are not part of any group (unassigned)
    users = User.query.filter(User.group == None).all()
    return render_template('groups/add_user_to_group.html', group=group, users=users, page='groups')


@groups_bp.route('/<group_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_group(group_id):
    group = Group.query.get_or_404(group_id)

    if request.method == 'POST':
        name = request.form.get('name')
        
        # Validate input
        if not name:
            flash('Group name is required!', 'danger')
            return redirect(url_for('groups.edit_group', group_id=group.id))

        # Check for duplicate name
        if Group.query.filter(Group.name == name, Group.id != group_id).first():
            flash('A group with this name already exists!', 'danger')
            return redirect(url_for('groups.edit_group', group_id=group.id))

        group.name = name
        db.session.commit()
        flash('Group updated successfully!', 'success')
        return redirect(url_for('groups.list_groups'))

    return render_template('groups/edit_group.html', group=group, page='groups')


@groups_bp.route('/<group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    group = Group.query.get_or_404(group_id)

    try:
        db.session.delete(group)
        db.session.commit()
        flash('Group deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting group: {e}', 'danger')

    return redirect(url_for('groups.list_groups'))



