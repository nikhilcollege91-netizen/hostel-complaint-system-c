from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'hostel_complaints.db'

# ---------------- Database helpers ----------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    room_no TEXT NOT NULL
                )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS complaints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER,
                    subject TEXT,
                    description TEXT,
                    status TEXT DEFAULT 'Pending',
                    remark TEXT DEFAULT '',
                    FOREIGN KEY (student_id) REFERENCES students(id)
                )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS wardens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )''')
    cur.execute("INSERT OR IGNORE INTO wardens (id, username, password) VALUES (1, 'warden', 'warden123')")
    conn.commit()
    conn.close()

# ---------------- Home ----------------
@app.route('/')
def home():
    return render_template('index.html')

# ---------------- Student Register ----------------
@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        room_no = request.form['room_no']

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO students (name, email, password, room_no) VALUES (?, ?, ?, ?)",
                         (name, email, password, room_no))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('student_login'))
        except sqlite3.IntegrityError:
            flash('Email already registered.', 'danger')
        finally:
            conn.close()
    return render_template('student_register.html')

# ---------------- Student Login ----------------
@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM students WHERE email=? AND password=?", (email, password)).fetchone()
        conn.close()
        if user:
            session['student_id'] = user['id']
            session['student_name'] = user['name']
            flash('Login successful!', 'success')
            return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('student_login.html')

# ---------------- Student Dashboard ----------------
@app.route('/student/dashboard')
def student_dashboard():
    if 'student_id' not in session:
        return redirect(url_for('student_login'))
    conn = get_db_connection()
    complaints = conn.execute("SELECT * FROM complaints WHERE student_id=?", (session['student_id'],)).fetchall()
    conn.close()
    return render_template('student_dashboard.html', complaints=complaints, name=session['student_name'])

# ---------------- Add Complaint ----------------
@app.route('/student/add_complaint', methods=['GET', 'POST'])
def add_complaint():
    if 'student_id' not in session:
        return redirect(url_for('student_login'))
    if request.method == 'POST':
        subject = request.form['subject']
        description = request.form['description']
        conn = get_db_connection()
        conn.execute("INSERT INTO complaints (student_id, subject, description) VALUES (?, ?, ?)",
                     (session['student_id'], subject, description))
        conn.commit()
        conn.close()
        flash('Complaint submitted successfully!', 'success')
        return redirect(url_for('student_dashboard'))
    return render_template('add_complaint.html')

# ---------------- Warden Login ----------------
@app.route('/warden/login', methods=['GET', 'POST'])
def warden_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        warden = conn.execute("SELECT * FROM wardens WHERE username=? AND password=?", (username, password)).fetchone()
        conn.close()
        if warden:
            session['warden'] = True
            flash('Warden logged in successfully!', 'success')
            return redirect(url_for('warden_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('warden_login.html')

# ---------------- Warden Dashboard ----------------
@app.route('/warden/dashboard')
def warden_dashboard():
    if 'warden' not in session:
        return redirect(url_for('warden_login'))
    conn = get_db_connection()
    complaints = conn.execute('''SELECT complaints.*, students.name, students.room_no
                                 FROM complaints
                                 JOIN students ON complaints.student_id = students.id''').fetchall()
    conn.close()
    return render_template('warden_dashboard.html', complaints=complaints)

# ---------------- Update Complaint Status ----------------
@app.route('/warden/update/<int:complaint_id>', methods=['POST'])
def update_complaint(complaint_id):
    if 'warden' not in session:
        return redirect(url_for('warden_login'))
    status = request.form['status']
    remark = request.form['remark']
    conn = get_db_connection()
    conn.execute("UPDATE complaints SET status=?, remark=? WHERE id=?", (status, remark, complaint_id))
    conn.commit()
    conn.close()
    flash('Complaint updated successfully!', 'success')
    return redirect(url_for('warden_dashboard'))

# ---------------- Logout ----------------
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))

# ---------------- Initialize ----------------
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
