Hostel Complaint System - Flask + C (shared library) scaffold
-----------------------------------------------------------

What this scaffold provides:
- A C source (complaints.c) that implements basic SQLite-backed complaint functions and builds a `libcomplaints.so`.
- A Flask app (`app.py`) that uses `ctypes` to call into `libcomplaints.so`.
- Templates and static files copied from the original Python project so UI remains identical.
- Dockerfile for Render: multi-stage build compiles C library then builds the Python image.

How to use locally:
1. Build the C shared lib:
   make

2. Run the Flask app:
   python app.py

3. Or build Docker image and run:
   docker build -t hostel-c-flask .
   docker run -p 5000:5000 hostel-c-flask

Deploying to Render:
- Create a new Web Service.
- Connect the repo (or upload this project).
- Render will run `docker build` automatically and deploy the container.

Notes & limitations:
- This scaffold focuses on complaint CRUD in C. Authentication and advanced features from the original app are kept in the Flask layer or can be migrated later.
- Password hashing and session management are easier in Python; keep them in Flask unless you want to reimplement in C.