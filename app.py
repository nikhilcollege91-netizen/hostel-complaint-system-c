
import os
import sqlite3
import mimetypes
import json
from flask import Flask, render_template, request, redirect, url_for, session, g, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import ctypes

# ------------------ App Setup ------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key')
app.config['DATABASE'] = 'hostel.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'mp3', 'wav', 'm4a', 'aac'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load C shared library
lib = None
lib_path = os.path.join(os.path.dirname(__file__), 'libcomplaints.so')
if os.path.exists(lib_path):
    lib = ctypes.CDLL(lib_path)
    lib.init_db.argtypes = [ctypes.c_char_p]
    lib.init_db.restype = ctypes.c_int
    lib.add_complaint.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.add_complaint.restype = ctypes.c_int
    lib.get_complaints_json_for_student.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.get_complaints_json_for_student.restype = ctypes.c_char_p
    lib.update_status.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
    lib.update_status.restype = ctypes.c_int
    lib.add_remark.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
    lib.add_remark.restype = ctypes.c_int
    lib.list_complaints_count.argtypes = [ctypes.c_char_p]
    lib.list_complaints_count.restype = ctypes.c_int
    # initialize DB
    lib.init_db(app.config['DATABASE'].encode('utf-8'))

# ------------------ Database helpers (for users & auth) ------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ------------------ Routes (kept mostly same, but complaint operations call C lib) ------------------

@app.route('/')
def index():
    count = 0
    if lib:
        count = lib.list_complaints_count(app.config['DATABASE'].encode('utf-8'))
    return render_template('index.html', count=count)

# Student register/login/dashboard/profile similar to original (kept in Python)
# For brevity, only key routes that changed (add_complaint, my_complaints, warden update) are included here.

@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        db = get_db()
        try:
            db.execute('INSERT INTO users (name,email,password) VALUES (?,?,?)', (name,email,password))
            db.commit()
            flash('Registered successfully! Please login.', 'success')
            return redirect(url_for('student_login'))
        except Exception as e:
            flash('Error registering: ' + str(e), 'danger')
    return render_template('student_register.html')

@app.route('/student/login', methods=['GET','POST'])
def student_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if user and check_password_hash(user['password'], password) and not user['is_warden']:
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_warden'] = False
            return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('student_login.html')

@app.route('/student/dashboard')
def student_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('student_login'))
    return render_template('student_dashboard.html')

@app.route('/student/add_complaint', methods=['GET','POST'])
def add_complaint():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))

    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        description = request.form['description']
        proof_file = request.files.get('proof')
        filename = None
        if proof_file and proof_file.filename != '' and allowed_file(proof_file.filename):
            filename = secure_filename(proof_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            proof_file.save(filepath)

        if lib:
            rc = lib.add_complaint(app.config['DATABASE'].encode('utf-8'),
                                   int(session['user_id']),
                                   title.encode('utf-8'),
                                   category.encode('utf-8'),
                                   description.encode('utf-8'),
                                   (filename.encode('utf-8') if filename else None))
            if rc == 0:
                flash('Complaint submitted successfully!', 'success')
            else:
                flash('Failed to submit complaint (C backend)', 'danger')
        else:
            # fallback to Python insertion
            db = get_db()
            db.execute(
                'INSERT INTO complaints (student_id, title, category, description, proof_file) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], title, category, description, filename)
            )
            db.commit()
            flash('Complaint submitted (Python fallback)', 'success')

        return redirect(url_for('my_complaints'))

    return render_template('add_complaint.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

@app.route('/student/my_complaints')
def my_complaints():
    if 'user_id' not in session or session.get('is_warden'):
        return redirect(url_for('student_login'))
    complaints = []
    if lib:
        cstr = lib.get_complaints_json_for_student(app.config['DATABASE'].encode('utf-8'), int(session['user_id']))
        if cstr:
            try:
                complaints = json.loads(ctypes.cast(cstr, ctypes.c_char_p).value.decode('utf-8'))
            except Exception as e:
                complaints = []
    else:
        db = get_db()
        rows = db.execute('SELECT * FROM complaints WHERE student_id=? ORDER BY created_at DESC', (session['user_id'],)).fetchall()
        for r in rows:
            complaints.append(dict(r))
    return render_template('my_complaints.html', complaints=complaints)

# Warden routes: login and dashboard kept in Python; actions to update status and add remark call C lib
@app.route('/warden/login', methods=['GET', 'POST'])
def warden_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=? AND is_warden=1', (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_warden'] = True
            return redirect(url_for('warden_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('warden_login.html')

@app.route('/warden/dashboard')
def warden_dashboard():
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    db = get_db()
    complaints = db.execute('SELECT c.*, u.name as student_name FROM complaints c JOIN users u ON c.student_id=u.id ORDER BY created_at DESC').fetchall()
    return render_template('warden_dashboard.html', complaints=complaints)

@app.route('/warden/update_status/<int:id>', methods=['POST'])
def update_status(id):
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    status = request.form.get('status')
    if lib:
        rc = lib.update_status(app.config['DATABASE'].encode('utf-8'), int(id), status.encode('utf-8'))
        if rc == 0:
            flash('Status updated', 'success')
        else:
            flash('Failed to update (C backend)', 'danger')
    else:
        db = get_db()
        db.execute('UPDATE complaints SET status=? WHERE id=?', (status, id))
        db.commit()
        flash('Status updated (Python fallback)', 'success')
    return redirect(url_for('warden_dashboard'))

@app.route('/warden/add_remark/<int:id>', methods=['POST'])
def add_remark(id):
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    remark = request.form.get('remark')
    if lib:
        rc = lib.add_remark(app.config['DATABASE'].encode('utf-8'), int(id), remark.encode('utf-8'))
        if rc == 0:
            flash('Remark added', 'success')
        else:
            flash('Failed to add remark (C backend)', 'danger')
    else:
        db = get_db()
        db.execute('UPDATE complaints SET remark=? WHERE id=?', (remark, id))
        db.commit()
        flash('Remark added (Python fallback)', 'success')
    return redirect(url_for('warden_dashboard'))

@app.route('/warden/analytics')
def warden_analytics():
    if 'user_id' not in session or not session.get('is_warden'):
        return redirect(url_for('warden_login'))
    db = get_db()
    total = db.execute('SELECT COUNT(*) as c FROM complaints').fetchone()['c']
    pending = db.execute("SELECT COUNT(*) as c FROM complaints WHERE status='Pending'").fetchone()['c']
    resolved = db.execute("SELECT COUNT(*) as c FROM complaints WHERE status!='Pending'").fetchone()['c']
    return render_template('analytics.html', total=total, pending=pending, resolved=resolved)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
