# JobSphere Job Portal

## 1. Install
Python 3.10+ is recommended.

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

## 2. MySQL
Run `database.sql` in MySQL Workbench or:
```bash
mysql -u root -p < database.sql
```

## 3. Environment
Copy `.env.example` to `.env` and set the database and SMTP values.

For Gmail SMTP, enable 2-Step Verification on the Google account and create a Google App Password. Use the generated App Password as SMTP_PASSWORD. Do not use your normal Gmail password.

## 4. Run
```bash
python app.py
```
Open http://127.0.0.1:5000

## 5. Test
Register a Job Seeker -> receive OTP -> verify -> login -> search jobs -> apply with PDF.
Register an Employer -> verify -> login -> create company -> post job -> review applicants -> change status.

Never commit `.env` or uploaded resumes to source control.
