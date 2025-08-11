# migrate_add_approved.py  — run once, then you can delete this file
"""
Safe, one-off migration to add `approved` column to the `user` table.

What it does:
 - makes a timestamped backup of your sqlite DB (if applicable)
 - checks for existing `approved` column
 - adds `approved` INTEGER NOT NULL DEFAULT 0
 - marks existing admins as approved (approved = 1)

Usage:
    python migrate_add_approved.py
"""

import os
import sys
import shutil
from datetime import datetime
from sqlalchemy import text
from app import app, db

def backup_sqlite_db(db_uri: str):
    """
    If db_uri is sqlite:///path/to/file.db, make a timestamped copy.
    Returns the path of backup file or None if no sqlite DB detected.
    """
    if not db_uri:
        return None

    # expect format sqlite:///absolute-or-relative-path
    prefix = "sqlite:///"
    if db_uri.startswith(prefix):
        path = db_uri[len(prefix):]
        if not os.path.isabs(path):
            # relative to app root
            path = os.path.join(os.path.dirname(__file__), path)
        if os.path.exists(path):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"{path}.bak.{ts}"
            shutil.copy2(path, backup_path)
            return backup_path
        else:
            print(f"[WARN] SQLite file not found at: {path}")
            return None
    else:
        print("[INFO] Database URI is not sqlite. Skipping automatic backup.")
        return None

def main():
    try:
        db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        print(f"[INFO] DB URI: {db_uri}")

        # try to backup sqlite DB if possible (recommended)
        backup_path = backup_sqlite_db(db_uri)
        if backup_path:
            print(f"[OK] Backed up SQLite DB to: {backup_path}")
        else:
            print("[WARN] No automatic SQLite backup made. Ensure you have a DB backup before proceeding.")

        with app.app_context():
            # get table info
            info_rows = db.session.execute(text("PRAGMA table_info(user);")).fetchall()
            cols = [row[1] for row in info_rows]  # row[1] is the column name
            print(f"[INFO] Existing columns in 'user': {cols}")

            if 'approved' in cols:
                print("[OK] Column 'approved' already exists — nothing to do.")
                return 0

            print("[INFO] Adding 'approved' column to user table (INTEGER NOT NULL DEFAULT 0)...")
            # ALTER TABLE to add column
            db.session.execute(text("ALTER TABLE user ADD COLUMN approved INTEGER NOT NULL DEFAULT 0;"))
            db.session.commit()
            print("[OK] 'approved' column added.")

            # Mark existing admins as approved
            print("[INFO] Marking existing admin users as approved (approved = 1)...")
            db.session.execute(text("UPDATE user SET approved = 1 WHERE role = 'admin';"))
            db.session.commit()
            print("[OK] Existing admins marked approved.")

            print("[SUCCESS] Migration completed.")
            return 0

    except Exception as exc:
        print("[ERROR] Migration failed:", exc)
        # If you made changes and want to rollback:
        try:
            db.session.rollback()
        except Exception:
            pass
        return 1

if __name__ == "__main__":
    code = main()
    sys.exit(code)
