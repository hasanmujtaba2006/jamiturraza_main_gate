# 🏛️ Jamia Gate Management System
## Python (Flask) — Railway.app Deployment Guide
### No coding experience needed — follow step by step!

---

## 📁 FILES IN THIS PACKAGE

```
gate-system-python/
├── app.py               ← Main application (all logic here)
├── requirements.txt     ← Python packages (auto-installed)
├── Procfile             ← Tells Railway how to run the app
├── .env.example         ← Environment variables template
├── templates/           ← HTML pages
│   ├── base.html        ← Sidebar + layout
│   ├── login.html       ← Login page
│   ├── dashboard.html   ← Dashboard
│   ├── scanner.html     ← Gate scanner
│   ├── log.html         ← Entry/Exit log
│   ├── users.html       ← User management
│   ├── alerts.html      ← Security alerts
│   ├── audit.html       ← Audit log
│   └── reports.html     ← Reports
└── README.txt           ← This file
```

---

## 🚀 DEPLOYMENT ON RAILWAY (FREE)

### STEP 1 — Create a GitHub Account (if you don't have one)
1. Go to https://github.com
2. Click Sign Up → create free account
3. Verify your email

---

### STEP 2 — Upload Project to GitHub

1. Go to https://github.com/new
2. Repository name: `gate-system`
3. Select **Private** (recommended)
4. Click **Create repository**
5. On the next page, click **"uploading an existing file"**
6. Drag and drop ALL files from this folder (including the `templates` folder)
7. Click **Commit changes**

---

### STEP 3 — Create Railway Account

1. Go to https://railway.app
2. Click **"Start a New Project"**
3. Sign in with your GitHub account (click "Login with GitHub")
4. Authorize Railway to access GitHub

---

### STEP 4 — Deploy to Railway

1. On Railway dashboard, click **"New Project"**
2. Click **"Deploy from GitHub repo"**
3. Select your `gate-system` repository
4. Railway will automatically detect Python and start deploying!
5. Wait 2-3 minutes for deployment to finish
6. Click on the deployment → click **"Generate Domain"**
7. You'll get a free URL like: `gate-system.up.railway.app`

---

### STEP 5 — Set Environment Variables

1. In Railway dashboard, click on your project
2. Click **"Variables"** tab
3. Add these variables:

```
SECRET_KEY = any-random-string-like-MyGateSystem2024!
```

That's it! Railway handles everything else automatically.

---

### STEP 6 — Open Your App!

Visit: `https://your-app-name.up.railway.app`

**Default Login Accounts — Password: Admin@123**

| Role        | User ID       |
|-------------|---------------|
| Super Admin | ADMIN-001     |
| Admin       | ADMIN-002     |
| Guard       | GRD-004       |
| Supervisor  | SUP-001       |

> ⚠️ Change passwords after first login (edit user in User Management)

---

## 👥 WHO SEES WHAT

| Feature          | Guard | Supervisor | Admin | Super Admin |
|------------------|-------|------------|-------|-------------|
| Gate Scanner     | ✅    | ✅         | ✅    | ✅          |
| Entry/Exit Log   | ✅    | ✅         | ✅    | ✅          |
| Alerts           | ❌    | ✅         | ✅    | ✅          |
| User Management  | ❌    | ❌         | ✅    | ✅          |
| Audit Log        | ❌    | ❌         | ✅    | ✅          |
| Reports          | ❌    | ❌         | ✅    | ✅          |

---

## 🔐 SECURITY FEATURES

- ✅ Passwords hashed (bcrypt) — never stored as plain text
- ✅ Session auto-timeout after 1 hour
- ✅ Login lockout after 5 failed attempts (15 min)
- ✅ Role-based access control (RBAC)
- ✅ Every action logged in audit trail
- ✅ Inactive accounts blocked at gate with auto-alert
- ✅ Guard ID recorded on every entry/exit log
- ✅ CSV export for all reports

---

## ❓ COMMON ERRORS

**"Application Error" on Railway**
→ Click "Logs" in Railway dashboard to see the error
→ Most common: SECRET_KEY variable not set

**"Login not working"**
→ Make sure you're using exactly: Admin@123 (capital A)
→ Database is auto-created on first run

**App is slow to start**
→ Normal on free tier — Railway "sleeps" after 30 min inactivity
→ First request after sleep takes ~5-10 seconds

**Want to reset all data?**
→ In Railway → your project → click the database file
→ Or redeploy to start fresh

---

## 🔧 RUNNING LOCALLY (Optional)

If you want to test on your own computer first:

1. Install Python from https://python.org
2. Open Command Prompt / Terminal in the project folder
3. Run these commands one by one:

```
pip install -r requirements.txt
python app.py
```

4. Open browser: http://localhost:5000

---

*Built with Python 3.10+, Flask, SQLAlchemy, SQLite*
*Deploys free on Railway.app*
