import flask
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from models import db, Content, User, LoginPageContent
from sqlalchemy.exc import SQLAlchemyError

content_bp = Blueprint('content', __name__, url_prefix='/content')

# Error handler
def handle_db_error(error):
    db.session.rollback()
    flash(f"An error occurred: {str(error)}", "danger")


# View content for all users
@content_bp.route('/')
@login_required
def manage_login_content():
    content = LoginPageContent.query.first()
    if not content:
        content = LoginPageContent()
        db.session.add(content)
        db.session.commit()

    return render_template('content/manage_login_content.html', content=content, page='login-content')


# Edit content for a specific user
@content_bp.route('/edit', methods=['GET', 'POST'])
@login_required
def edit_login_content():
    content = LoginPageContent.query.first()

    if request.method == 'POST':
        logo_url = request.form.get('logo_url')
        phone_number = request.form.get('phone_number')
        slogan = request.form.get('slogan')
        contact_line=  request.form.get('contact_line')

        if content:
            content.logo_url = logo_url
            content.phone_number = phone_number
            content.slogan = slogan
            content.contact_line = contact_line

        else:
            content = LoginPageContent(logo_url=logo_url, phone_number=phone_number, slogan=slogan, contact_line=contact_line)
            db.session.add(content)

        try:
            db.session.commit()
            flash('Content updated successfully!', 'success')
            return redirect(url_for('content.manage_login_content'))
        except SQLAlchemyError as e:
            handle_db_error(e)

    return render_template('content/edit_login_content.html', content=content, page='login-content')



# View content for a specific user
@content_bp.route('/user/<string:user_id>')
@login_required
def manage_user_content(user_id):
    user = User.query.get_or_404(user_id)
    content = Content.query.filter_by(user_id=user_id).first()
    return render_template('content/manage_user_content.html', user=user, content=content)


# Edit content for a specific user
@content_bp.route('/edit/<string:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user_content(user_id):
    user = User.query.get_or_404(user_id)
    content = Content.query.filter_by(user_id=user_id).first()

    if request.method == 'POST':
        # logo_url = request.form.get('logo_url')
        # phone_number = request.form.get('phone_number')
        default_url = request.form.get('default_url')
        closing_dialog = request.form.get('closing_dialog')
        unassigned_proxy_error_dialog = request.form.get('unassigned_proxy_error_dialog')

        if content:
            # content.logo_url = logo_url
            # content.phone_number = phone_number
            content.default_url = default_url
            content.closing_dialog = closing_dialog
            content.unassigned_proxy_error_dialog = unassigned_proxy_error_dialog

        else:
            content = Content(default_url=default_url, user_id=user_id, closing_dialog=closing_dialog, unassigned_proxy_error_dialog=unassigned_proxy_error_dialog)
            db.session.add(content)

        try:
            db.session.commit()
            flash('Content updated successfully!', 'success')
            return redirect(url_for('content.manage_user_content', user_id=user_id))
        except SQLAlchemyError as e:
            handle_db_error(e)

    return render_template('content/edit_user_content.html', user=user, content=content)
