from functools import wraps
from flask import request, jsonify
import jwt
  # Adjust import for your project structure

def token_required(secret_key):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            from app import User
            token = request.cookies.get('jwt_token')  # Retrieve token from cookies
            if not token:
                return jsonify({'message': 'Token is missing!'}), 401

            try:
                # Decode token
                data = jwt.decode(token, secret_key, algorithms=['HS256'])
                current_user = User.query.filter_by(email=data['sub']).first()
                if not current_user:
                    return jsonify({'message': 'User not found!'}), 401
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired!'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token!'}), 401

            # Pass current_user to the protected route
            return f(current_user, *args, **kwargs)

        return decorated
    return decorator
