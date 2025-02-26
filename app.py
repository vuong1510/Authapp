import os
from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
import secrets


app = Flask(__name__)

# connects the app to the sql database and secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:D0Ge59PDT@localhost/users'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)

db = SQLAlchemy(app)

# flask login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# the model for the database table
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False) # should be hashed later

# creates the database tables
with app.app_context():
    db.create_all()

# loads the user
@login_manager.user_loader
def load_user(user_id):
    return(User.query.get(int(user_id)))

# login form class (flask-wtf)
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


# login route, logs in the user, does not take input yet
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Find the user by the username
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            return(redirect(url_for('home')))
        return("Invalid credentials.")
    
    return(render_template('login.html', form=form))

# logout route, logs out the user, obviously
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return(redirect(url_for('home')))

# home route
@app.route('/')
@app.route('/home')
def home():
    return(render_template('index.html'))

if __name__ == '__main__':
    app.run(debug=True)