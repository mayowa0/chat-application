import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from otp_helper import send_otp_to_email
from flask_session import Session
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')

# Ensure instance folder for DB/sessions exists
os.makedirs(app.instance_path, exist_ok=True)

POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PW = os.getenv("POSTGRES_PW", "yourpassword")
POSTGRES_DB = os.getenv("POSTGRES_DB", "chat_app")
POSTGRES_URL = os.getenv("POSTGRES_URL", "localhost:5432")

app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{POSTGRES_USER}:{POSTGRES_PW}@{POSTGRES_URL}/{POSTGRES_DB}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy after all configs are set
db = SQLAlchemy(app)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(app.instance_path, 'flask_session')
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
Session(app)

socketio = SocketIO(app, cors_allowed_origins="*")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class UserAuth(db.Model):
  #  __bind_key__ = 'auth'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

def generate_otp(length=6):
    """Generate a numeric OTP of given length."""
    digits = string.digits
    otp = ''.join(random.choice(digits) for _ in range(length))
    return otp

@app.route('/')
def index():
    if 'email' in session:
        return redirect(url_for('user_list'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            return render_template('signup.html', error="All fields are required")

        if User.query.filter_by(email=email).first():
            return render_template('signup.html', error="Email already exists")


        otp = generate_otp()
        try:
            send_otp_to_email(email, otp)
        except Exception as e:
            print("Email sending error:", e)
            return render_template('verify_otp.html', error="Couldn't send email. In dev, check server logs for the OTP.")

        session['temp_username'] = username
        session['temp_email'] = email
        session['temp_password'] = generate_password_hash(password)
        session['otp'] = otp

        return redirect(url_for('verify_otp'))

    return render_template('signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if not entered_otp:
            return render_template('verify_otp.html', error="Please enter the OTP.")

        if entered_otp == session.get('otp'):
            new_user = User(
                username=session.get('temp_username', 'User'),
                email=session.get('temp_email'),
                password=session.get('temp_password')
            )
            db.session.add(new_user)
            db.session.commit()

            session['email'] = new_user.email
            session['username'] = new_user.username

            # Clear temp data
            session.pop('temp_username', None)
            session.pop('temp_email', None)
            session.pop('temp_password', None)
            session.pop('otp', None)

            return redirect(url_for('user_list'))
        else:
            return render_template('verify_otp.html', error="Invalid OTP. Try again.")

    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['email'] = user.email
            session['username'] = user.username
            return redirect(url_for('user_list'))
        else:
            return render_template('login.html', error="Invalid email or password!")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/chat')
def user_list():
    if 'email' not in session:
        return redirect(url_for('login'))

    current_email = session['email']
    users = User.query.filter(User.email != current_email).all()
    return render_template('chat.html', users=users, current_user=session.get('username'))

# ---------- PRIVATE CHAT ----------
@app.route('/chat/<target_email>')
def chat_with_user(target_email):
    if 'email' not in session:
        return redirect(url_for('login'))

    current_email = session['email']
    target_user = User.query.filter_by(email=target_email).first()
    if not target_user:
        return "User not found", 404

    room = "_".join(sorted([current_email, target_email]))
    return render_template(
        'chat_room.html',
        room=room,
        target_user=target_user,
        current_user=session.get('username')
    )

# ----------------- SOCKET.IO EVENTS -----------------
@socketio.on('join_room')
def handle_join_room(data):
    room = data.get('room')
    if room:
        join_room(room)
        send(f"{session.get('username','Unknown')} has entered the room.", to=room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data.get('room')
    if room:
        leave_room(room)
        send(f"{session.get('username','Unknown')} has left the room.", to=room)

@socketio.on('message')
def handle_message(data):
    room = data.get('room')
    msg = data.get('message')
    if room and msg:
        sender = session.get('username', session.get('email', 'Someone'))
        send({'sender': sender, 'message': msg}, to=room)

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or "").strip().lower()
    password = (data.get('password') or "")

    if not email or not password:
        return jsonify({"message": "Email and password required"}), 400

    if UserAuth.query.filter_by(email=email).first():
        return jsonify({"message": "Email already exists"}), 400

    hashed_pw = generate_password_hash(password)
    new_user = UserAuth(email=email, password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Signed up successfully"}), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or "").strip().lower()
    password = (data.get('password') or "")

    user = UserAuth.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        return jsonify({"message": "Logged in successfully"}), 200

    return jsonify({"message": "Invalid email or password"}), 401

with app.app_context():
    db.create_all()             

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)

