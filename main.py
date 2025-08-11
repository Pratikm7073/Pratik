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
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory
from werkzeug.security import generate_password_hash
from datetime import datetime
from sqlalchemy.orm import backref
import re



app = Flask(__name__)
app.secret_key = 'Pratik@123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_login_system.db'
db = SQLAlchemy(app)
UPLOAD_FOLDER = 'uploads' #for uploading
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  ##for uploading
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

users = {}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    approved = db.Column(db.Boolean, nullable=False, default=False)   # <-- new field

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    deadline = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='Active')  # 'Active' or 'Completed'

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'),    nullable=False)
    project = db.relationship('Project', backref=db.backref('assignments', cascade='all, delete'))
    user    = db.relationship('User',    backref=db.backref('assignments', cascade='all, delete'))

from sqlalchemy.orm import backref

class Document(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    filename   = db.Column(db.String(200), nullable=False)
    filepath   = db.Column(db.String(300), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

    project = db.relationship(
        'Project',
        backref=backref('documents', cascade='all, delete-orphan')
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username'].strip()
        pwd = request.form['password']
        confirm = request.form.get('confirm_password', '')

        # Basic checks
        if not uname or not pwd:
            flash("❗ Username and password required.", "danger")
            return redirect(url_for('register'))

        if pwd != confirm:
            flash("❗ Password and confirmation do not match.", "danger")
            return redirect(url_for('register'))

        existing = User.query.filter_by(username=uname).first()
        if existing:
            flash("❗ Username already taken. Please choose another.", "danger")
            return redirect(url_for('register'))

        # Hash password
        hashed = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create new user in unapproved state
        otp_secret = pyotp.random_base32()
        new_user = User(
            username=uname,
            password=hashed,
            otp_secret=otp_secret,
            role='developer',
            approved=False
        )
        db.session.add(new_user)
        db.session.commit()

        flash("✅ Registered successfully! Your account is pending admin approval.", "info")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not username or not password:
            flash("Please enter username and password.", "danger")
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

        # password check using bcrypt (stored hashes should be utf-8 strings)
        try:
            valid_pw = bcrypt.checkpw(password.encode('utf-8'),
                                       user.password.encode('utf-8'))
        except Exception:
            valid_pw = False

        if not valid_pw:
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

        # Ensure account approved by admin before starting 2FA
        if not getattr(user, 'approved', False):
            flash("Your account is pending admin approval. Please wait.", "warning")
            return redirect(url_for('login'))

        # Good -> save in session and go to 2FA page
        session['pre_2fa_user_id'] = user.id
        return redirect(url_for('verify_otp'))

    # GET
    return render_template('login.html')

@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    # Only admins may access
    if current_user.role != 'admin':
        return "Access denied. Admins only.", 403

    # Handle role-update form submission (this route is used only for role updates)
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_role = request.form.get('role')

        if not user_id or not new_role:
            flash("❗ Missing form data.", "danger")
            return redirect(url_for('manage_users'))

        user = User.query.get(user_id)
        if not user:
            flash("❌ User not found.", "danger")
            return redirect(url_for('manage_users'))

        # Prevent self-demotion: admin shouldn't remove their own admin role here
        if user.id == current_user.id and new_role != 'admin':
            flash("❗ You cannot demote your own admin role.", "warning")
            return redirect(url_for('manage_users'))

        user.role = new_role
        db.session.commit()
        flash(f"✅ {user.username} is now a {new_role}.", "success")
        return redirect(url_for('manage_users'))

    # GET: prepare lists for template
    users_list = User.query.order_by(User.username).all()

    # pending = users who haven't been approved yet
    # ensure your User model has an 'approved' boolean column
    try:
        pending = User.query.filter_by(approved=False).order_by(User.username).all()
    except Exception:
        # If the DB/schema isn't in sync and 'approved' doesn't exist, fall back gracefully
        pending = []

    return render_template('manage_users.html', users=users_list, pending=pending)

@app.route('/admin/create_user', methods=['POST'])
@login_required
def create_user():
    # Only admins may access
    if current_user.role != 'admin':
        return "Access denied. Admins only.", 403

    uname = request.form.get('username', '').strip()
    pwd = request.form.get('password', '')
    pwd2 = request.form.get('confirm_password', '')
    role = request.form.get('role', 'developer')

    if not uname or not pwd or not pwd2:
        flash("❌ Username, password and confirmation are all required.", "danger")
        return redirect(url_for('manage_users'))

    if pwd != pwd2:
        flash("❌ The two passwords do not match.", "danger")
        return redirect(url_for('manage_users'))

    # password policy (same as before)
    policy = r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[{\]};:\'",<.>/?]).{10,}$'
    if not re.match(policy, pwd):
        flash(
            "❌ Password must be at least 10 characters long, include "
            "one uppercase letter, one number, and one special character.",
            "danger"
        )
        return redirect(url_for('manage_users'))

    if User.query.filter_by(username=uname).first():
        flash(f"❗ Username '{uname}' already exists.", "danger")
        return redirect(url_for('manage_users'))

    hashed = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    otp_secret = pyotp.random_base32()

    # Admin-created users are approved immediately
    new_user = User(username=uname, password=hashed, otp_secret=otp_secret, role=role, approved=True)
    db.session.add(new_user)
    db.session.commit()

    flash(f"✅ User '{uname}' created with role '{role}' and approved.", "success")
    return redirect(url_for('manage_users'))

@app.route('/admin/approve_user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if current_user.role != 'admin':
        return "Access denied. Admins only.", 403

    user = User.query.get_or_404(user_id)
    user.approved = True
    db.session.commit()
    flash(f"✅ User '{user.username}' has been approved.", "success")
    return redirect(url_for('manage_users'))


@app.route('/admin/reject_user/<int:user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    if current_user.role != 'admin':
        return "Access denied. Admins only.", 403

    user = User.query.get_or_404(user_id)
    # Option 1: delete the account
    db.session.delete(user)
    db.session.commit()
    flash(f"❌ User '{user.username}' has been rejected and deleted.", "info")
    return redirect(url_for('manage_users'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_pw = request.form['old_password']
        new_pw = request.form['new_password']
        confirm = request.form['confirm_password']

        # 1) Verify old password
        if not bcrypt.checkpw(old_pw.encode('utf-8'), current_user.password.encode('utf-8')):
            flash("❌ Old password is incorrect.", "danger")
            return redirect(url_for('change_password'))

        # 2) Check new passwords match
        if new_pw != confirm:
            flash("❌ New passwords do not match.", "danger")
            return redirect(url_for('change_password'))

        # 3) Hash & save the new password
        hashed = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        current_user.password = hashed
        db.session.commit()

        flash("✅ Your password has been updated.", "success")
        return redirect(url_for('dashboard'))

    # GET
    return render_template('change_password.html')

    # GET request: show all users
    users = User.query.order_by(User.username).all()
    return render_template('manage_users.html', users=users)

@app.route('/upload_document', methods=['GET', 'POST'])
@login_required
def upload_document():
    # Only admins and leads can upload
    if current_user.role not in ('admin', 'project_lead'):
        flash("Access denied.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        project_id = request.form['project_id']
        file = request.files.get('document')
        if file and file.filename:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Create the Document record
            doc = Document(filename=filename, filepath=filepath, project_id=project_id)
            db.session.add(doc)
            db.session.commit()
            flash("✅ Document uploaded!")
            return redirect(url_for('upload_document'))

    # GET: show projects based on role
    if current_user.role == 'admin':
        projects = Project.query.all()
    else:  # project_lead
        # optional: filter to only that lead’s projects if you add lead_id to Project
        projects = Project.query.filter_by(status='Active').all()

    return render_template('upload_document.html', projects=projects)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    # Serve files from the UPLOAD_FOLDER
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@login_required
@app.route('/project/<int:project_id>/documents')
@login_required
def view_documents(project_id):
    # Fetch the project or 404
    project = Project.query.get_or_404(project_id)

    # Permission check
    if current_user.role == 'admin':
        pass  # admins see all
    elif current_user.role == 'project_lead':
        # optionally filter by lead ownership if you have lead_id
        pass
    elif current_user.role == 'developer':
        # developers only if assigned
        assigned = Assignment.query.filter_by(
            project_id=project_id,
            user_id=current_user.id
        ).first()
        if not assigned:
            return "Access denied.", 403
    else:
        return "Access denied.", 403

    # Load all docs for this project
    documents = Document.query.filter_by(project_id=project_id).all()
    return render_template('view_documents.html', project=project, documents=documents)

    
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
 
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    # Only admins may delete
    if current_user.role != 'admin':
        return "Access denied. Admins only.", 403

    # Prevent self-deletion
    if user_id == current_user.id:
        flash("❌ You cannot delete your own account.", "danger")
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"🗑️ User '{user.username}' deleted.", "success")
    return redirect(url_for('manage_users')) 

@app.route('/projects')
@login_required
def view_projects():
    # Show all projects, regardless of status
    projects = Project.query.order_by(Project.deadline).all()
    return render_template('view_projects.html', projects=projects)

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
    totp_uri = pyotp.totp.TOTP(current_user.op_secret).provisioning_uri(
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

from flask import flash, redirect, url_for, render_template, request, session
from flask_login import login_user

@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    # session key must match the one used in login()
    user_id = session.get('pre_2fa_user_id')

    if not user_id:
        flash("Session expired or invalid access.", "danger")
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        session.pop('pre_2fa_user_id', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_input = (request.form.get('otp') or '').strip()
        if not otp_input:
            flash("Please enter the 6-digit code from your authenticator app.", "danger")
            return redirect(url_for('verify_otp'))

        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp_input):
            # Success: clear pre-2fa marker, set otp_verified, login_user
            session.pop('pre_2fa_user_id', None)
            session['otp_verified'] = True
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for('verify_otp'))

    # GET -> show QR and otp input
    otp_uri = pyotp.TOTP(user.otp_secret).provisioning_uri(
        name=user.username, issuer_name="PixelForge Nexus"
    )
    qr_img = qrcode.make(otp_uri)
    buffer = BytesIO()
    qr_img.save(buffer, format="PNG")
    buffer.seek(0)
    qrcode_data = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return render_template('verify.html', qrcode_data=qrcode_data)

@app.route('/lead/assign', methods=['GET', 'POST'])
@login_required
def assign_developer():
    # only project_leads may assign
    if current_user.role != 'project_lead':
        return "Access denied. Leads only.", 403

    if request.method == 'POST':
        project_id = int(request.form['project_id'])
        user_id    = int(request.form['user_id'])

        # avoid duplicate
        exists = Assignment.query.filter_by(project_id=project_id, user_id=user_id).first()
        if not exists:
            db.session.add(Assignment(project_id=project_id, user_id=user_id))
            db.session.commit()
            flash("✅ Developer assigned!")
        else:
            flash("❗ That developer is already assigned.", "warning")

        return redirect(url_for('assign_developer'))

    # GET: show only projects *that this lead owns*—
    # for now, show all active projects; you can adjust to filter by lead’s own projects
    projects  = Project.query.filter_by(status='Active').all()
    developers = User.query.filter_by(role='developer').all()
    return render_template('assign.html', projects=projects, developers=developers)

@app.route('/my_projects')
@login_required
def my_projects():
    # 1) Only developers can access this page
    if current_user.role != 'developer':
        return "Access denied. Developers only.", 403

    # 2) Fetch all Assignment rows for this user
    assignments = Assignment.query.filter_by(user_id=current_user.id).all()

    # 3) Extract the Project objects
    projects = [a.project for a in assignments]

    # 4) Render the template, passing in the list
    return render_template('my_projects.html', projects=projects)


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

