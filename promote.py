# promote.py
from main import app, db, User  # adjust import if your main file has a different name

with app.app_context():
    # Look up user by exact username (case‑sensitive)
    user = User.query.filter_by(username='Pratik7073').first()
    if user:
        user.role = 'admin'
        db.session.commit()
        print(f"{user.username} is now an {user.role}")
    else:
        print("User 'Pratik7073' not found in the database.")
