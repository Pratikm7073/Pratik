from flask import flash
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import io
import bcrypt
import base64
from qrcode.image.pil import PilImage
from forms import OTPForm
from flask_login import UserMixin
from flask import request, redirect, url_for, flash
from flask_login import current_user, login_required
from datetime import datetime
from flask_login import login_user
from io import BytesIO





app = Flask(__name__)
app.secret_key = 'Pratik@123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_login_system.db'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

users = {}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    deadline = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='Active')  # 'Active' or 'Completed'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']

        # Generate bcrypt hash and decode to string
        hashed_bytes = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
        hashed = hashed_bytes.decode('utf-8')

        otp_secret = pyotp.random_base32()

        # Create new user in the database
        new_user = User(
            username=uname,
            password=hashed,
            otp_secret=otp_secret,
            role='developer'
        )
        db.session.add(new_user)
        db.session.commit()

        flash("✅ Registered successfully! Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session['pre_2fa_user_id'] = user.id  # ✅ Save in session
            return redirect(url_for('verify_otp'))  # Redirect to OTP page
        else:
            flash("Invalid credentials")  # ✅ Properly indented
            return redirect(url_for('login'))  # ✅ Properly indented
    return render_template('login.html')

from datetime import datetime

@app.route('/make_admin')
def make_admin():
    from flask_login import current_user
    if not current_user.is_authenticated or current_user.role != 'admin':
        return "Access denied. Only an admin can assign roles."

    username_to_update = 'Pratik7073'  # Change this if needed
    user = User.query.filter_by(username=username_to_update).first()

    if user:
        user.role = 'admin'
        db.session.commit()
        return f"User '{username_to_update}' has been updated to admin."
    else:
        return f"User '{username_to_update}' not found."

@app.route('/make_admin_temp')
def make_admin_temp():
    user = User.query.filter_by(username='Pratik7073').first()
    if user:
        user.role = 'admin'
        db.session.commit()
        return "User 'Pratik7073' is now an admin."
    return "User not found."


@app.route('/admin/create_project', methods=['GET', 'POST'])
@login_required
def create_project():
    if current_user.role != 'admin':
        return "Access denied. Admins only."

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        deadline_str = request.form['deadline']
        deadline = datetime.strptime(deadline_str, '%Y-%m-%d').date()  # Convert string to date

        new_project = Project(
            name=name,
            description=description,
            deadline=deadline
        )

        db.session.add(new_project)
        db.session.commit()
        flash("✅ Project created successfully!")
        return redirect(url_for('create_project'))

    projects = Project.query.all()
    return render_template('create_project.html', projects=projects)


@app.route('/admin/delete_project/<int:project_id>')
@login_required
def delete_project(project_id):
    if current_user.role != 'admin':
        return "Access denied. Admins only."

    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    flash("❌ Project deleted successfully!")
    return redirect(url_for('create_project'))


@app.route('/projects')
@login_required
def view_projects():
    # Show only Active projects
    active_projects = Project.query.filter_by(status='Active').all()
    return render_template('view_projects.html', projects=active_projects)

@app.route('/admin/complete_project/<int:project_id>', methods=['POST'])
@login_required
def complete_project(project_id):
    if current_user.role != 'admin':
        return "Access denied. Admins only."

    project = Project.query.get_or_404(project_id)
    project.status = 'Completed'
    db.session.commit()
    return redirect(url_for('view_projects'))


@app.route('/admin/complete_project/<int:project_id>', methods=['POST'])
@login_required
def mark_project_completed(project_id):
    if current_user.role != 'admin':
        return "Access denied. Admins only."

    project = Project.query.get_or_404(project_id)
    project.status = 'Completed'
    db.session.commit()
    return redirect(url_for('view_projects'))


def qrcode_image():
    # Generate the TOTP URI
    totp_uri = pyotp.totp.TOTP(current_user.otp_secret).provisioning_uri(
        name=current_user.username, issuer_name="SecureLoginSystem")

    # Generate QR code using default settings
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

    # Save image to bytes
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    return base64.b64encode(buf.read()).decode('utf-8')

@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    user_id = session.get('pre_2fa_user_id')  # Ensure consistent key name

    if not user_id:
        flash("Session expired or invalid access.")
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if not user:
        flash("User not found.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_input = request.form.get('otp')
        totp = pyotp.TOTP(user.otp_secret)

        if totp.verify(otp_input):
            session.pop('pre_2fa_user_id', None)
            session['otp_verified'] = True  # ✅ Set OTP verified flag
            login_user(user)  # ✅ Keep user logged in
            flash("Login successful.")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP. Please try again.")

    # ✅ Generate QR code (for first-time setup)
    otp_uri = pyotp.totp.TOTP(user.otp_secret).provisioning_uri(
        name=user.username,
        issuer_name="PixelForge Nexus")
    qr_img = qrcode.make(otp_uri)
    buffer = BytesIO()
    qr_img.save(buffer, format="PNG")
    qrcode_data = base64.b64encode(buffer.getvalue()).decode()

    return render_template("verify.html", qrcode_data=qrcode_data)


@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('otp_verified'):
        return redirect(url_for('verify_otp'))
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This creates the missing tables like 'user'
    app.run(debug=True)


if __name__ == '__main__':
    app.run(debug=True)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
try:
    csrf = CSRFProtect(app)
except Exception as e:
    print("CSRF setup failed:", e)

