from flask import Flask, make_response, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from dotenv import load_dotenv
import jwt
import datetime
from flask_migrate import Migrate

load_dotenv()

# Accessing environment variables
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
MODERATOR_EMAIL = os.getenv('MODERATOR_EMAIL')
MODERATOR_PASSWORD = os.getenv('MODERATOR_PASSWORD')


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
db = SQLAlchemy(app)
login_manager = LoginManager(app)


# Define the User and Article models

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(80), nullable=False)  # Role field (admin, user, moderator)

    def __repr__(self):
        return f"<User {self.email}>"

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('articles', lazy=True))

    def __repr__(self):
        return f"<Article {self.title}>"
    
migrate = Migrate(app, db)

# Decorator for protecting routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt_token')  # Retrieve token from cookies
        if not token:
            return jsonify({'message': 'JWT Token is missing!'}), 401

        try:
            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
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

    

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes and Views

@app.route('/')
def home():
    articles = Article.query.all()
    return render_template('home.html', articles=articles)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='POST':
        email = request.form['email']
        password = request.form['password']

        # Hardcoded login check for admin and moderator
         # Check for admin credentials
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            admin_user = User.query.filter_by(email=email).first()

            # If admin user does not exist, create them
            if not admin_user:
                admin_user = User(
                    username = 'administrator',
                    email=email, 
                    role='admin', 
                    password=generate_password_hash(password, method='pbkdf2:sha256')
                )
                db.session.add(admin_user)
                db.session.commit()
            
            role = 'admin'
            login_user(admin_user)

        # Check for moderator credentials
        elif email == MODERATOR_EMAIL and password == MODERATOR_PASSWORD:
            moderator_user = User.query.filter_by(email=email).first()

            # If moderator user does not exist, create them
            if not moderator_user:
                moderator_user = User(
                    username='moderator',
                    email=email, 
                    role='moderator', 
                    password=generate_password_hash(password, method='pbkdf2:sha256')
                )
                db.session.add(moderator_user)
                db.session.commit()
            
            role = 'moderator'
            login_user(moderator_user)

        else:
            #user = User.query.filter_by(email=email).first()
            user = User.query.filter((User.email == email)).first()
            if user and check_password_hash(user.password, password):
                role = user.role
                login_user(user)
            else:
                flash('Login Unsuccessful. Please check email and password.', 'danger')
                return redirect(url_for('login'))

        # Create JWT token
        
        token = jwt.encode({
            'sub': email,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # 1 hour expiration
        }, app.config['SECRET_KEY'], algorithm='HS256')

        #return jsonify({'message': 'Login successful', 'token': token})
        response = make_response(redirect(url_for('home' if role != 'admin' else 'admin')))
        response.set_cookie('jwt_token', token, httponly=True, secure=False)  # httponly=True prevents JS access
        flash('Login successful', 'success')
        return response

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    response = make_response(redirect(url_for('home')))  
    response.delete_cookie('jwt_token')  
    logout_user()
    flash('You have been logged out.', 'success')
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('login'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken. Please choose another one.', 'danger' )
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Default role is 'user' for new registrations
        new_user = User(username=username, email=email, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/post', methods=['GET', 'POST'])
@token_required
def post_article(current_user):
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        new_article = Article(title=title, content=content, author=current_user)
        db.session.add(new_article)
        db.session.commit()
        flash('Article posted successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('post_article.html')


@app.route('/delete_article' , methods = ['GET'])
#@login_required
@token_required
def delete_article(current_user):
    if current_user.role not in ['moderator', 'admin']:
        flash("You don't have permission to access this page.", 'danger')
        return redirect(url_for('home'))
    
    articles = Article.query.all()
    return render_template('delete_article.html', articles = articles)


@app.route('/delete_article/<int:id>', methods=['POST'])
#@login_required
@token_required
def delete_article_by_id(current_user, id):
    article = Article.query.get_or_404(id)
    
    if current_user.role == 'moderator' or current_user.role == 'admin':
        db.session.delete(article)
        db.session.commit()
        flash('Article deleted successfully!', 'success')
        return redirect(url_for('home'))
    flash('You do not have permission to delete this article.', 'danger')
    return redirect(url_for('home'))



@app.route('/admin', methods=['GET', 'POST'])
# @login_required
@token_required
def admin(current_user):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)    
        db.session.commit()
        flash('User created successfully!', 'success')
    
    users = User.query.filter(User.role!='admin').all()
    return render_template('admin.html', users=users)

@app.route('/delete_user/<int:id>', methods=['POST'])
#@login_required
@token_required
def delete_user(current_user, id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(id)
    if user != current_user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('You cannot delete your own account.', 'danger')
    return redirect(url_for('admin'))

@app.route('/edit_role/<int:id>', methods=['POST'])
# @login_required
@token_required
def edit_role(current_user, id):
    if current_user.role != 'admin':
        return jsonify({'message': 'Permission Denied. Admin role required'}), 403
    
    user = User.query.get_or_404(id)
    new_role = request.form.get('role')

    if new_role not in ['user', 'moderator', 'admin']:
        return jsonify({'message': 'Invalid role specified'}), 400
    
    user.role = new_role
    db.session.commit()

    flash(f"Role for {user.email} updated to {new_role} successfully!", "success")
    return redirect(url_for('admin'))
    

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
