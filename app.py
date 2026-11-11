import os, secrets, smtplib, hashlib
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-secret-key")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
UPLOAD_FOLDER = os.path.join(app.root_path, "uploads", "resumes")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"pdf"}

def db():
    url = os.getenv("DATABASE_URL", "")
    if url:
        # Expected: mysql://user:password@host:3306/database
        from urllib.parse import urlparse
        p = urlparse(url)
        return mysql.connector.connect(
            host=p.hostname, port=p.port or 3306, user=p.username,
            password=p.password, database=p.path.lstrip("/")
        )
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "job_portal")
    )

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def protect_csrf():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
            abort(400, "Invalid CSRF token")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def role_required(role):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if session.get("role") != role:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco

def send_otp(email, otp):
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    sender = os.getenv("SMTP_EMAIL")
    password = os.getenv("SMTP_PASSWORD")
    if not all([host, sender, password]):
        raise RuntimeError("SMTP is not configured. Set SMTP_HOST, SMTP_EMAIL and SMTP_PASSWORD.")
    msg = EmailMessage()
    msg["Subject"] = "Your Job Portal verification OTP"
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(f"Your Job Portal OTP is {otp}. It expires in 5 minutes.")
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)

def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.context_processor
def inject_user():
    return {"current_user": session.get("user_name"), "current_role": session.get("role")}

@app.route("/")
def index():
    conn = db(); cur = conn.cursor(dictionary=True)
    cur.execute("""SELECT j.*, c.name AS company_name FROM jobs j
                   JOIN companies c ON c.id=j.company_id
                   WHERE j.is_active=1 ORDER BY j.created_at DESC LIMIT 6""")
    jobs = cur.fetchall()
    cur.close(); conn.close()
    return render_template("index.html", jobs=jobs)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("full_name","").strip()
        email = request.form.get("email","").strip().lower()
        phone = request.form.get("phone","").strip()
        password = request.form.get("password","")
        confirm = request.form.get("confirm_password","")
        role = request.form.get("role","job_seeker")
        if not name or not email or not phone or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")
        if password != confirm or len(password) < 8:
            flash("Passwords must match and contain at least 8 characters.", "error")
            return render_template("register.html")
        if role not in ("job_seeker", "employer"):
            flash("Invalid user type.", "error")
            return render_template("register.html")
        conn = db(); cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        exists = cur.fetchone()
        if exists:
            cur.close(); conn.close()
            flash("An account with that email already exists.", "error")
            return render_template("register.html")
        cur.execute("SELECT created_at FROM otp_verification WHERE email=%s ORDER BY created_at DESC LIMIT 1", (email,))
        recent = cur.fetchone()
        if recent and datetime.now() - recent["created_at"] < timedelta(seconds=60):
            cur.close(); conn.close()
            flash("Please wait 60 seconds before requesting another OTP.", "error")
            return render_template("register.html")
        otp = f"{secrets.randbelow(1000000):06d}"
        cur.execute("DELETE FROM otp_verification WHERE email=%s", (email,))
        cur.execute("""INSERT INTO otp_verification
                       (email, otp_hash, expires_at, attempts, created_at)
                       VALUES (%s,%s,%s,0,NOW())""",
                    (email, hash_otp(otp), datetime.now()+timedelta(minutes=5)))
        conn.commit()
        cur.close(); conn.close()
        try:
            send_otp(email, otp)
        except Exception as e:
            conn = db(); cur = conn.cursor()
            cur.execute("DELETE FROM otp_verification WHERE email=%s", (email,))
            conn.commit(); cur.close(); conn.close()
            flash(f"Could not send OTP. Check SMTP settings. ({e})", "error")
            return render_template("register.html")
        session["pending_registration"] = {
            "name": name, "email": email, "phone": phone,
            "password_hash": generate_password_hash(password), "role": role
        }
        flash("OTP sent to your email.", "success")
        return redirect(url_for("verify_otp"))
    return render_template("register.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    pending = session.get("pending_registration")
    if not pending:
        return redirect(url_for("register"))
    if request.method == "POST":
        otp = request.form.get("otp","").strip()
        conn = db(); cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM otp_verification WHERE email=%s", (pending["email"],))
        row = cur.fetchone()
        if not row:
            flash("OTP not found. Please register again.", "error")
        elif row["attempts"] >= 5:
            flash("Too many incorrect attempts. Please register again.", "error")
        elif datetime.now() > row["expires_at"]:
            flash("OTP expired. Please register again or resend.", "error")
        elif not secrets.compare_digest(hash_otp(otp), row["otp_hash"]):
            cur2 = conn.cursor()
            cur2.execute("UPDATE otp_verification SET attempts=attempts+1 WHERE id=%s", (row["id"],))
            conn.commit(); cur2.close()
            flash("Incorrect OTP.", "error")
        else:
            cur2 = conn.cursor()
            cur2.execute("""INSERT INTO users(full_name,email,phone,password_hash,role,is_verified)
                            VALUES(%s,%s,%s,%s,%s,1)""",
                         (pending["name"],pending["email"],pending["phone"],pending["password_hash"],pending["role"]))
            user_id = cur2.lastrowid
            if pending["role"] == "job_seeker":
                cur2.execute("INSERT INTO job_seekers(user_id) VALUES(%s)", (user_id,))
            else:
                cur2.execute("INSERT INTO employers(user_id) VALUES(%s)", (user_id,))
            cur2.execute("DELETE FROM otp_verification WHERE email=%s", (pending["email"],))
            conn.commit(); cur2.close()
            session.pop("pending_registration", None)
            flash("Registration successful. Please log in.", "success")
            cur.close(); conn.close()
            return redirect(url_for("login"))
        cur.close(); conn.close()
    return render_template("verify_otp.html", email=pending["email"])

@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    pending = session.get("pending_registration")
    if not pending:
        return redirect(url_for("register"))
    conn = db(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT created_at FROM otp_verification WHERE email=%s ORDER BY created_at DESC LIMIT 1", (pending["email"],))
    row = cur.fetchone()
    if row and datetime.now() - row["created_at"] < timedelta(seconds=60):
        cur.close(); conn.close(); flash("Please wait before resending OTP.", "error")
        return redirect(url_for("verify_otp"))
    otp = f"{secrets.randbelow(1000000):06d}"
    cur.execute("DELETE FROM otp_verification WHERE email=%s", (pending["email"],))
    cur.execute("""INSERT INTO otp_verification(email,otp_hash,expires_at,attempts,created_at)
                   VALUES(%s,%s,%s,0,NOW())""",
                (pending["email"],hash_otp(otp),datetime.now()+timedelta(minutes=5)))
    conn.commit(); cur.close(); conn.close()
    try:
        send_otp(pending["email"], otp)
        flash("A new OTP was sent.", "success")
    except Exception as e:
        flash(f"Could not send OTP: {e}", "error")
    return redirect(url_for("verify_otp"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        conn=db(); cur=conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email=%s AND is_verified=1", (email,))
        user=cur.fetchone(); cur.close(); conn.close()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")
        session.clear()
        session["csrf_token"] = secrets.token_urlsafe(32)
        session["user_id"]=user["id"]; session["user_name"]=user["full_name"]; session["role"]=user["role"]
        return redirect(url_for("seeker_dashboard" if user["role"]=="job_seeker" else "employer_dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

def job_query():
    q=request.args.get("q","").strip()
    location=request.args.get("location","").strip()
    job_type=request.args.get("job_type","").strip()
    min_salary=request.args.get("min_salary","").strip()
    sql="""SELECT j.*, c.name AS company_name FROM jobs j
            JOIN companies c ON c.id=j.company_id WHERE j.is_active=1"""
    args=[]
    if q:
        sql += " AND (j.title LIKE %s OR j.skills LIKE %s OR j.description LIKE %s)"
        like=f"%{q}%"; args += [like,like,like]
    if location:
        sql += " AND j.location LIKE %s"; args.append(f"%{location}%")
    if job_type:
        sql += " AND j.job_type=%s"; args.append(job_type)
    if min_salary.isdigit():
        sql += " AND j.salary >= %s"; args.append(int(min_salary))
    sql += " ORDER BY j.created_at DESC"
    conn=db(); cur=conn.cursor(dictionary=True); cur.execute(sql,args); jobs=cur.fetchall()
    cur.close(); conn.close(); return jobs

@app.route("/jobs")
def jobs():
    return render_template("jobs.html", jobs=job_query())

@app.route("/job/<int:job_id>")
def job_details(job_id):
    conn=db(); cur=conn.cursor(dictionary=True)
    cur.execute("""SELECT j.*, c.name AS company_name, c.description AS company_description
                   FROM jobs j JOIN companies c ON c.id=j.company_id WHERE j.id=%s AND j.is_active=1""",(job_id,))
    job=cur.fetchone(); cur.close(); conn.close()
    if not job: abort(404)
    return render_template("job_details.html", job=job)

@app.route("/seeker")
@login_required
@role_required("job_seeker")
def seeker_dashboard():
    conn=db(); cur=conn.cursor(dictionary=True)
    cur.execute("""SELECT a.*, j.title, c.name AS company_name FROM applications a
                   JOIN jobs j ON j.id=a.job_id JOIN companies c ON c.id=j.company_id
                   WHERE a.user_id=%s ORDER BY a.applied_at DESC""",(session["user_id"],))
    applications=cur.fetchall()
    cur.execute("SELECT * FROM job_seekers WHERE user_id=%s",(session["user_id"],)); profile=cur.fetchone()
    cur.close(); conn.close()
    return render_template("seeker_dashboard.html", applications=applications, profile=profile)

@app.route("/apply/<int:job_id>", methods=["POST"])
@login_required
@role_required("job_seeker")
def apply(job_id):
    f=request.files.get("resume")
    if not f or not f.filename or not allowed_file(f.filename):
        flash("Please upload a PDF resume.", "error"); return redirect(url_for("job_details",job_id=job_id))
    conn=db(); cur=conn.cursor(dictionary=True)
    cur.execute("SELECT id FROM jobs WHERE id=%s AND is_active=1",(job_id,)); job=cur.fetchone()
    cur.execute("SELECT id FROM applications WHERE job_id=%s AND user_id=%s",(job_id,session["user_id"])); existing=cur.fetchone()
    if not job:
        cur.close(); conn.close(); abort(404)
    if existing:
        cur.close(); conn.close(); flash("You already applied for this job.","error"); return redirect(url_for("job_details",job_id=job_id))
    filename=f"{session['user_id']}_{secrets.token_hex(8)}.pdf"
    f.save(os.path.join(app.config["UPLOAD_FOLDER"],secure_filename(filename)))
    cur2=conn.cursor()
    cur2.execute("""INSERT INTO applications(job_id,user_id,resume_filename,status)
                    VALUES(%s,%s,%s,'Pending')""",(job_id,session["user_id"],filename))
    conn.commit(); cur2.close(); cur.close(); conn.close()
    flash("Application submitted successfully.","success")
    return redirect(url_for("seeker_dashboard"))

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    conn=db(); cur=conn.cursor(dictionary=True)
    if request.method=="POST":
        phone=request.form.get("phone","").strip()
        cur2=conn.cursor()
        cur2.execute("UPDATE users SET phone=%s WHERE id=%s",(phone,session["user_id"]))
        if session["role"]=="job_seeker":
            cur2.execute("""UPDATE job_seekers SET skills=%s, experience=%s, education=%s
                            WHERE user_id=%s""",(request.form.get("skills",""),request.form.get("experience",""),
                            request.form.get("education",""),session["user_id"]))
        conn.commit(); cur2.close(); flash("Profile updated.","success")
    cur.execute("""SELECT u.full_name,u.email,u.phone,u.role,js.skills,js.experience,js.education
                   FROM users u LEFT JOIN job_seekers js ON js.user_id=u.id WHERE u.id=%s""",(session["user_id"],))
    user=cur.fetchone(); cur.close(); conn.close()
    return render_template("profile.html", user=user)

@app.route("/employer")
@login_required
@role_required("employer")
def employer_dashboard():
    conn=db(); cur=conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM companies WHERE employer_id=%s",(session["user_id"],)); company=cur.fetchone()
    jobs=[]; applicants=[]
    if company:
        cur.execute("SELECT * FROM jobs WHERE company_id=%s ORDER BY created_at DESC",(company["id"],)); jobs=cur.fetchall()
        cur.execute("""SELECT a.*, j.title, u.full_name,u.email,u.phone FROM applications a
                       JOIN jobs j ON j.id=a.job_id JOIN users u ON u.id=a.user_id
                       WHERE j.company_id=%s ORDER BY a.applied_at DESC""",(company["id"],))
        applicants=cur.fetchall()
    cur.close(); conn.close()
    return render_template("employer_dashboard.html",company=company,jobs=jobs,applicants=applicants)

@app.route("/company", methods=["POST"])
@login_required
@role_required("employer")
def company():
    name=request.form.get("name","").strip(); description=request.form.get("description","").strip()
    if not name: flash("Company name is required.","error"); return redirect(url_for("employer_dashboard"))
    conn=db(); cur=conn.cursor(dictionary=True)
    cur.execute("SELECT id FROM companies WHERE employer_id=%s",(session["user_id"],)); existing=cur.fetchone()
    cur2=conn.cursor()
    if existing:
        cur2.execute("UPDATE companies SET name=%s,description=%s WHERE id=%s",(name,description,existing["id"]))
    else:
        cur2.execute("INSERT INTO companies(employer_id,name,description) VALUES(%s,%s,%s)",(session["user_id"],name,description))
    conn.commit(); cur2.close(); cur.close(); conn.close()
    flash("Company profile saved.","success"); return redirect(url_for("employer_dashboard"))

@app.route("/post-job", methods=["GET","POST"])
@login_required
@role_required("employer")
def post_job():
    if request.method=="POST":
        conn=db(); cur=conn.cursor(dictionary=True)
        cur.execute("SELECT id FROM companies WHERE employer_id=%s",(session["user_id"],)); company=cur.fetchone()
        if not company:
            cur.close(); conn.close(); flash("Create your company profile first.","error"); return redirect(url_for("employer_dashboard"))
        title=request.form.get("title","").strip(); location=request.form.get("location","").strip()
        job_type=request.form.get("job_type","Full-time"); skills=request.form.get("skills","").strip()
        description=request.form.get("description","").strip(); requirements=request.form.get("requirements","").strip()
        salary=request.form.get("salary","0")
        try: salary=int(salary)
        except: salary=0
        if not title or not location or not description:
            cur.close(); conn.close(); flash("Title, location and description are required.","error")
            return render_template("post_job.html")
        cur2=conn.cursor()
        cur2.execute("""INSERT INTO jobs(company_id,title,location,salary,job_type,skills,description,requirements)
                       VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (company["id"],title,location,salary,job_type,skills,description,requirements))
        conn.commit(); cur2.close(); cur.close(); conn.close()
        flash("Job posted.","success"); return redirect(url_for("employer_dashboard"))
    return render_template("post_job.html")

@app.route("/job/<int:job_id>/delete", methods=["POST"])
@login_required
@role_required("employer")
def delete_job(job_id):
    conn=db(); cur=conn.cursor()
    cur.execute("""UPDATE jobs j JOIN companies c ON c.id=j.company_id
                   SET j.is_active=0 WHERE j.id=%s AND c.employer_id=%s""",(job_id,session["user_id"]))
    conn.commit(); cur.close(); conn.close(); flash("Job removed.","success")
    return redirect(url_for("employer_dashboard"))

@app.route("/application/<int:application_id>/status", methods=["POST"])
@login_required
@role_required("employer")
def application_status(application_id):
    status=request.form.get("status","Pending")
    if status not in ("Pending","Shortlisted","Rejected","Selected"): abort(400)
    conn=db(); cur=conn.cursor()
    cur.execute("""UPDATE applications a JOIN jobs j ON j.id=a.job_id
                   JOIN companies c ON c.id=j.company_id
                   SET a.status=%s WHERE a.id=%s AND c.employer_id=%s""",
                (status,application_id,session["user_id"]))
    conn.commit(); cur.close(); conn.close()
    flash("Application status updated.","success"); return redirect(url_for("employer_dashboard"))

@app.route("/resume/<filename>")
@login_required
@role_required("employer")
def resume(filename):
    # Only allow employers to access resumes belonging to their own job applicants.
    conn=db(); cur=conn.cursor(dictionary=True)
    cur.execute("""SELECT a.id FROM applications a JOIN jobs j ON j.id=a.job_id
                   JOIN companies c ON c.id=j.company_id
                   WHERE a.resume_filename=%s AND c.employer_id=%s""",(filename,session["user_id"]))
    ok=cur.fetchone(); cur.close(); conn.close()
    if not ok: abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

@app.errorhandler(400)
def bad_request(e): return render_template("error.html", code=400, message=str(e)), 400
@app.errorhandler(403)
def forbidden(e): return render_template("error.html", code=403, message="Access denied."), 403
@app.errorhandler(404)
def not_found(e): return render_template("error.html", code=404, message="Page not found."), 404

if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
