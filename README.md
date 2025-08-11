PixelForge Nexus – Secure Role-Based Project Management System
PixelForge Nexus is a secure project management web application built with Flask.
It implements multi-factor authentication (MFA), role-based access control (RBAC), and secure design principles to ensure safe user access and document management.

🚀 Features
Secure Login with MFA (TOTP)
Passwords stored using strong hashing (bcrypt)
Two-factor authentication via Time-based One-Time Passwords (TOTP)
Role-Based Access Control
Admin – Manage users, create projects, upload documents
Project Lead – Assign developers, upload documents
Developer – View assigned projects and documents
Account Approval System
New registrations require admin approval before login is allowed
Project & Document Management
Create, assign, and track projects
Upload & access documents securely
Secure File Uploads
Sanitized file names (secure_filename)
Stored in dedicated uploads directory
🛡 Secure Design Principles Applied
Least Privilege – Users have access only to what their role permits
Defense in Depth – MFA + password hashing + session protection
Secure Defaults – All accounts start inactive until approved by an admin
Data Protection – Strong password hashing (bcrypt) and secure OTP secrets
Auditability – Admins can manage and track users & projects
