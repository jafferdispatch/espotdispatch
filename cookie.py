from flask import Blueprint, request, jsonify
from models import db, Cookie

cookie_api = Blueprint('cookie_api', __name__)

@cookie_api.route('/store-cookies', methods=['POST'])
def store_cookies():
    try:
        data = request.get_json()
        username = data.get('username')
        cookies = data.get('cookies')

        if not username or not cookies:
            return jsonify({'error': 'Username and cookies are required'}), 400

        # Check if a record for the user already exists
        existing_record = Cookie.query.filter_by(username=username).first()

        if existing_record:
            # Update existing record
            existing_record.cookies = cookies
        else:
            # Create new record
            new_record = Cookie(username=username, cookies=cookies)
            db.session.add(new_record)

        db.session.commit()
        return jsonify({'message': 'Cookies stored successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@cookie_api.route('/retrieve-cookies', methods=['POST'])
def retrieve_cookies():
    try:
        data = request.get_json()
        username = data.get('username')

        if not username:
            return jsonify({'error': 'Username is required'}), 400

        # Retrieve cookies for the user
        record = Cookie.query.filter_by(username=username).first()

        if not record:
            return jsonify({'error': 'No cookies found for this user'}), 404

        return jsonify({'cookies': record.cookies}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
