import os, secrets
from flask import Flask, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired

app = Flask(__name__)

# connects the app to the sql database and secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:D0Ge59PDT@localhost/users'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'verysecretkey123'

db = SQLAlchemy(app)

# OAuth
oauth = OAuth(app)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True

microsoft = oauth.register(
    name = 'microsoft',
    client_id = os.getenv('AZURE_CLIENT_ID'),
    client_secret = os.getenv('AZURE_CLIENT_SECRET'),
    server_metadata_url = f'https://login.microsoftonline.com/{os.getenv("AZURE_TENANT_ID")}/v2.0/.well-known/openid-configuration',
    client_kwargs = {'scope': 'User.Read openid profile offline_access'}
)

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


# login form class (flask-wtf)
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


# loads the user
@login_manager.user_loader
def load_user(user_id):
    return(User.query.get(int(user_id)))


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


@app.route('/login-microsoft')
def login_microsoft():
    redirect_uri = url_for('getAToken', _external=True)
    return(microsoft.authorize_redirect(redirect_uri))


@app.route('/getAToken')
def getAToken():
    # retrieve the access token from Microsoft OAuth
    token = microsoft.authorize_access_token()

    # store the token in the session for future use
    session['access_token'] = token

    # get user information from the Microsoft Graph API, currently we're doing nothing with it
    user_info = microsoft.get('https://graph.microsoft.com/v1.0/me').json()

    user = User.query.filter_by(username=user_info['userPrincipalName']).first()

    # if the user does not exist, create a new one
    if user is None:
        user = User(username=user_info['userPrincipalName'], password='')
        db.session.add(user)
        db.session.commit()
    
    # Log the user in
    login_user(user)

    #Redirect to the home page
    return(redirect(url_for('home')))


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