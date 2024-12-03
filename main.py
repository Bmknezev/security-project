import base64
import io
import json
import os
from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_session import Session
import pyotp
import qrcode

app = Flask(__name__)

# Configure session
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

USER_FILE = 'users.json'


# Helper function to read the users from the file
def read_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, 'r') as f:
        return json.load(f)


# Helper function to save users to the file
def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f)


# Route for the login screen
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        users = read_users()
        # Validate user credentials
        if username in users:
            if password == users[username]['password']:
                session['username'] = username
                return redirect('/otp')
            else:
                flash('Invalid credentials. Please try again.', 'danger')
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')


# Route for OTP verification
@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if request.method == 'POST':
        entered_otp = request.form.get('OTP')

        users = read_users()
        user_code = users[session['username']]['code']
        # check if first 3 number are 123, if yes then remove them and proceed
        if entered_otp[:len(user_code)] == user_code:
            entered_otp = entered_otp[len(user_code):]

            # Get the secret key for the user
            secret = users[session['username']]['secret']
            # Verify the OTP
            if pyotp.TOTP(secret).verify(entered_otp):
                flash('Login successful!', 'success')
                return redirect('/dashboard')
            else:
                flash('Invalid OTP. Please try again.', 'danger')
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('otp.html')


# Simple dashboard (for successful login)
@app.route('/dashboard')
def dashboard():
    return f"Welcome!"


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        code = request.form.get('code')

        users = read_users()
        # Check if the user already exists
        if username in users:
            flash('Username already exists. Please choose another.', 'danger')
        else:
            totp = pyotp.TOTP(pyotp.random_base32())
            secret = totp.secret
            users[username] = {'password': password, 'code': code, 'secret': secret}
            save_users(users)
            uri = totp.provisioning_uri(name=username, issuer_name="MyApp")

            qr = qrcode.make(uri)
            img_byte_arr = io.BytesIO()
            qr.save(img_byte_arr, format='PNG')
            img_byte_arr.seek(0)

            flash('Account created successfully!', 'success')
            return redirect(url_for('qr_code', username=username))  # Redirect to login page

    return render_template('signup.html')


def generate_qr_code(username):
    users = read_users()
    totp = pyotp.TOTP(users[username]['secret'])
    # Generate the OTP URL for Google Authenticator
    uri = totp.provisioning_uri(name=username, issuer_name="MyApp")

    # Create the QR code
    qr = qrcode.make(uri)

    # Save QR code to a byte stream to display on the web
    img_byte_arr = io.BytesIO()
    qr.save(img_byte_arr, format='PNG')
    img_byte_arr.seek(0)

    img_base64 = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')
    return img_base64


@app.route('/qr_code/<username>')
def qr_code(username):
    # Generate the QR code for the given user email
    img_byte_arr = generate_qr_code(username)

    # Render the QR code page
    return render_template('qr.html', user_email=username, img_byte_arr=img_byte_arr)


if __name__ == '__main__':
    app.run(debug=True, port=8080, host='127.0.0.1')
