# debug_list_users.py
from main import app, db, User  # adjust import if your main module name differs
with app.app_context():
    for u in User.query.order_by(User.username).all():
        print(u.id, u.username, getattr(u, 'role', None), getattr(u, 'approved', None))
