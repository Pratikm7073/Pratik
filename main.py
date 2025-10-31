# main.py — cleaned and fixed version
import os
import io
import re
import base64
import bcrypt
import pyotp
import qrcode
from io import BytesIO
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.utils import secure_filename
from sqlalchemy.orm import backref

# --- App / DB setup ---
app = Flask(__name__)
app.secret_key = "Pratik@123"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///secure_login_system.db"
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    otp_secret = db.Column(db.String(32), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="developer")
    password = db.Column(db.String(200), nullable=False)
    approved = db.Column(db.Boolean, nullable=False, default=False)


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    deadline = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default="Active")


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    project = db.relationship("Project", backref=db.backref("assignments", cascade="all, delete"))
    user = db.relationship("User", backref=db.backref("assignments", cascade="all, delete"))


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    filepath = db.Column(db.String(300), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)

    project = db.relationship("Project", backref=backref("documents", cascade="all, delete-orphan"))


# --- Login loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Routes ---
@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        uname = (request.form.get("username") or "").strip()
        pwd = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""

        if not uname or not pwd:
            flash("❗ Username and password required.", "danger")
            return redirect(url_for("register"))

        if pwd != confirm:
            flash("❗ Password and confirmation do not match.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=uname).first():
            flash("❗ Username already taken. Please choose another.", "danger")
            return redirect(url_for("register"))

        hashed = bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        otp_secret = pyotp.random_base32()
        new_user = User(username=uname, password=hashed, otp_secret=otp_secret, role="developer", approved=False)

        db.session.add(new_user)
        db.session.commit()

        flash("✅ Registered successfully! Your account is pending admin approval.", "info")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Please enter username and password.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        try:
            valid_pw = bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8"))
        except Exception:
            valid_pw = False

        if not valid_pw:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        # check approval
        if not getattr(user, "approved", False):
            flash("Your account is pending admin approval. Please wait.", "warning")
            return redirect(url_for("login"))

        # store pre-2fa and go to verify
        session["pre_2fa_user_id"] = user.id
        return redirect(url_for("verify_otp"))

    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        flash("Session expired or invalid access.", "danger")
        return redirect(url_for("login"))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        session.pop("pre_2fa_user_id", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_input = (request.form.get("otp") or "").strip()
        if not otp_input:
            flash("Please enter the 6-digit code from your authenticator app.", "danger")
            return redirect(url_for("verify_otp"))

        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp_input):
            session.pop("pre_2fa_user_id", None)
            session["otp_verified"] = True
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for("verify_otp"))

    # GET: generate qrcode for setup/display
    otp_uri = pyotp.TOTP(user.otp_secret).provisioning_uri(name=user.username, issuer_name="PixelForge Nexus")
    qr_img = qrcode.make(otp_uri)
    buffer = BytesIO()
    qr_img.save(buffer, format="PNG")
    buffer.seek(0)
    qrcode_data = base64.b64encode(buffer.getvalue()).decode("utf-8")

    return render_template("verify.html", qrcode_data=qrcode_data)


@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    # Only admins may access
    if current_user.role != 'admin':
        return "Access denied. Admins only.", 403

    # POST here is for role updates coming from the existing-users table.
    if request.method == 'POST':
        # Expecting form fields: user_id and role
        user_id = request.form.get('user_id')
        new_role = request.form.get('role')

        if not user_id or not new_role:
            flash("❗ Missing data for updating role.", "danger")
            return redirect(url_for('manage_users'))

        user = User.query.get(user_id)
        if not user:
            flash("❌ User not found.", "danger")
            return redirect(url_for('manage_users'))

        # Prevent admin from demoting themself accidentally
        if user.id == current_user.id and new_role != 'admin':
            flash("❗ You cannot demote your own admin role here.", "warning")
            return redirect(url_for('manage_users'))

        user.role = new_role
        db.session.commit()
        flash(f"✅ {user.username} role updated to {new_role}.", "success")
        return redirect(url_for('manage_users'))

    # GET: render page, include pending list for approvals
    users_list = User.query.order_by(User.username).all()

    # If approved column exists, fetch pending users; otherwise empty list
    try:
        pending = User.query.filter_by(approved=False).order_by(User.username).all()
    except Exception:
        pending = []

    return render_template('manage_users.html', users=users_list, pending=pending)


@app.route("/admin/create_user", methods=["POST"])
@login_required
def create_user():
    if current_user.role != "admin":
        return "Access denied. Admins only.", 403

    uname = (request.form.get("username") or "").strip()
    pwd = request.form.get("password") or ""
    pwd2 = request.form.get("confirm_password") or ""
    role = request.form.get("role") or "developer"

    if not uname or not pwd or not pwd2:
        flash("❌ Username, password and confirmation are all required.", "danger")
        return redirect(url_for("manage_users"))

    if pwd != pwd2:
        flash("❌ The two passwords do not match.", "danger")
        return redirect(url_for("manage_users"))

    policy = r"^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[{\]};:'\",<.>/?]).{10,}$"
    if not re.match(policy, pwd):
        flash("❌ Password must be at least 10 characters long, include one uppercase letter, one number, and one special character.", "danger")
        return redirect(url_for("manage_users"))

    if User.query.filter_by(username=uname).first():
        flash(f"❗ Username '{uname}' already exists.", "danger")
        return redirect(url_for("manage_users"))

    hashed = bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    otp_secret = pyotp.random_base32()
    new_user = User(username=uname, password=hashed, otp_secret=otp_secret, role=role, approved=True)
    db.session.add(new_user)
    db.session.commit()

    flash(f"✅ User '{uname}' created with role '{role}' and approved.", "success")
    return redirect(url_for("manage_users"))


@app.route("/admin/approve_user/<int:user_id>", methods=["POST"])
@login_required
def approve_user(user_id):
    if current_user.role != "admin":
        return "Access denied. Admins only.", 403

    user = User.query.get_or_404(user_id)
    user.approved = True
    db.session.commit()
    flash(f"✅ User '{user.username}' has been approved.", "success")
    return redirect(url_for("manage_users"))


@app.route("/admin/reject_user/<int:user_id>", methods=["POST"])
@login_required
def reject_user(user_id):
    if current_user.role != "admin":
        return "Access denied. Admins only.", 403

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"❌ User '{user.username}' has been rejected and deleted.", "info")
    return redirect(url_for("manage_users"))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != "admin":
        return "Access denied. Admins only.", 403

    if user_id == current_user.id:
        flash("❌ You cannot delete your own account.", "danger")
        return redirect(url_for("manage_users"))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"🗑️ User '{user.username}' deleted.", "success")
    return redirect(url_for("manage_users"))


@app.route("/projects")
@login_required
def view_projects():
    projects = Project.query.order_by(Project.deadline).all()
    return render_template("view_projects.html", projects=projects)


@app.route("/admin/create_project", methods=["GET", "POST"])
@login_required
def create_project():
    if current_user.role != "admin":
        return "Access denied. Admins only.", 403

    if request.method == "POST":
        name = request.form.get("name", "")
        description = request.form.get("description", "")
        deadline_str = request.form.get("deadline", "")
        try:
            deadline = datetime.strptime(deadline_str, "%Y-%m-%d").date()
        except Exception:
            flash("❗ Invalid deadline format. Use YYYY-MM-DD.", "danger")
            return redirect(url_for("create_project"))

        new_project = Project(name=name, description=description, deadline=deadline)
        db.session.add(new_project)
        db.session.commit()
        flash("✅ Project created successfully!")
        return redirect(url_for("create_project"))

    projects = Project.query.all()
    return render_template("create_project.html", projects=projects)


@app.route("/admin/complete_project/<int:project_id>", methods=["POST"])
@login_required
def complete_project(project_id):
    if current_user.role != "admin":
        return "Access denied. Admins only.", 403

    project = Project.query.get_or_404(project_id)
    project.status = "Completed"
    db.session.commit()
    return redirect(url_for("view_projects"))


@app.route("/upload_document", methods=["GET", "POST"])
@login_required
def upload_document():
    if current_user.role not in ("admin", "project_lead"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        project_id = request.form.get("project_id")
        file = request.files.get("document")
        if file and file.filename:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            doc = Document(filename=filename, filepath=filepath, project_id=project_id)
            db.session.add(doc)
            db.session.commit()
            flash("✅ Document uploaded!")
            return redirect(url_for("upload_document"))

    if current_user.role == "admin":
        projects = Project.query.all()
    else:
        projects = Project.query.filter_by(status="Active").all()
    return render_template("upload_document.html", projects=projects)


@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/project/<int:project_id>/documents")
@login_required
def view_documents(project_id):
    project = Project.query.get_or_404(project_id)

    if current_user.role == "admin":
        pass
    elif current_user.role == "project_lead":
        pass
    elif current_user.role == "developer":
        assigned = Assignment.query.filter_by(project_id=project_id, user_id=current_user.id).first()
        if not assigned:
            return "Access denied.", 403
    else:
        return "Access denied.", 403

    documents = Document.query.filter_by(project_id=project_id).all()
    return render_template("view_documents.html", project=project, documents=documents)


@app.route("/lead/assign", methods=["GET", "POST"])
@login_required
def assign_developer():
    if current_user.role != "project_lead":
        return "Access denied. Leads only.", 403

    if request.method == "POST":
        project_id = int(request.form.get("project_id"))
        user_id = int(request.form.get("user_id"))

        exists = Assignment.query.filter_by(project_id=project_id, user_id=user_id).first()
        if not exists:
            db.session.add(Assignment(project_id=project_id, user_id=user_id))
            db.session.commit()
            flash("✅ Developer assigned!")
        else:
            flash("❗ That developer is already assigned.", "warning")
        return redirect(url_for("assign_developer"))

    projects = Project.query.filter_by(status="Active").all()
    developers = User.query.filter_by(role="developer").all()
    return render_template("assign.html", projects=projects, developers=developers)


@app.route("/my_projects")
@login_required
def my_projects():
    if current_user.role != "developer":
        return "Access denied. Developers only.", 403

    assignments = Assignment.query.filter_by(user_id=current_user.id).all()
    projects = [a.project for a in assignments]
    return render_template("my_projects.html", projects=projects)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_pw = request.form.get("old_password", "")
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not bcrypt.checkpw(old_pw.encode("utf-8"), current_user.password.encode("utf-8")):
            flash("❌ Old password is incorrect.", "danger")
            return redirect(url_for("change_password"))

        if new_pw != confirm:
            flash("❌ New passwords do not match.", "danger")
            return redirect(url_for("change_password"))

        hashed = bcrypt.hashpw(new_pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        current_user.password = hashed
        db.session.commit()
        flash("✅ Your password has been updated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


@app.route("/dashboard")
@login_required
def dashboard():
    if not session.get("otp_verified"):
        return redirect(url_for("verify_otp"))
    return render_template("dashboard.html", username=current_user.username)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))


# --- Start app & create DB if needed ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
if __name__ == "__main__":
    with app.app_context():
        print("Registered endpoints:")
        for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
            print(f"{rule.endpoint:40s}  -> {rule.rule}")
        db.create_all()
    app.run(debug=True)
