<pre>
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ █████╗ ███████╗███╗   ███╗      ██████╗ ██████╗ 
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔════╝████╗ ████║      ██╔══██╗██╔══██╗
██████╔╝███████║███████║██╔██╗ ██║   ██║   ███████║███████╗██╔████╔██║█████╗██║  ██║██████╔╝
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██╔══██║╚════██║██║╚██╔╝██║╚════╝██║  ██║██╔══██╗
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ██║  ██║███████║██║ ╚═╝ ██║      ██████╔╝██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝      ╚═════╝ ╚═════╝ 
                                                                                              
        █████╗  ██████╗████████╗██╗██╗   ██╗███████╗    ██████╗ ███████╗███████╗███████╗
       ██╔══██╗██╔════╝╚══██╔══╝██║██║   ██║██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔════╝
       ███████║██║        ██║   ██║██║   ██║█████╗      ██║  ██║█████╗  █████╗  ███████╗
       ██╔══██║██║        ██║   ██║╚██╗ ██╔╝██╔══╝      ██║  ██║██╔══╝  ██╔══╝  ╚════██║
       ██║  ██║╚██████╗   ██║   ██║ ╚████╔╝ ███████╗    ██████╔╝███████╗██║     ███████║
       ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝    ╚═════╝ ╚══════╝╚═╝     ╚══════╝

                    ███████╗██╗  ██╗██████╗      ███████╗ ██████╗  ██████╗
                    ██╔════╝██║  ██║██╔══██╗     ██╔════╝██╔═══██╗██╔════╝
                    █████╗  ███████║██████╔╝     ███████╗██║   ██║██║     
                    ██╔══╝  ██╔══██║██╔══██╗     ╚════██║██║   ██║██║     
                    ███████╗██║  ██║██║  ██║     ███████║╚██████╔╝╚██████╗
                    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝
</pre>

**Phantasm-DB** is a fully functional, three-tier Electronic Health Record (EHR) system featuring a built-in **Security Operations Center (SOC)** and a sophisticated **Honeypot Architecture (The Shadow Vault)**. 

To a legitimate user, it acts as a secure clinical portal for doctors and patients. To an attacker, it becomes an invisible labyrinth that safely traps them in a mirrored fake database while logging their every move in real-time.

## 🌟 Core Features

### 🏥 Clinical Portals (The Surface)
* **Provider Dashboard:** Manage patient rosters, update diagnoses, track treatment plans, schedule appointments, and export clinical notes to PDF.
* **Patient Portal:** View active prescriptions, upcoming appointments, and daily treatment compliance tasks.
* **Secure Authentication:** Passwordless OTP (One-Time Password) login flow with JWT session management and Role-Based Access Control (RBAC).

### 🕸️ Active Defense & Honeypot (The Trap)
* **Real-time Threat Scanning:** The login layer intercepts and scans inputs for SQL Injection (SQLi), Cross-Site Scripting (XSS), and Command Injection.
* **Invisible Flagging:** When an attack payload is detected, the attacker's IP is silently blacklisted in the `monitor.threat_actors` table.
* **The Shadow Vault:** Flagged IPs are secretly issued a tainted JWT (`honeypot: true`). All their subsequent API requests are silently routed to a fake, mirrored database schema (`shadow_vault`) populated with dummy data. The attacker never knows they failed to breach the real database.

### 📊 Security Operations Center (The Overwatch)
* **Forensic Ledger:** Every action taken by a trapped attacker is recorded with their payload, target table, and IP address.
* **Live Audit Logs:** Monitor clean logins versus malicious attempts.
* **Threat Management:** Admins can view flagged IPs, review attack payloads, and clear threat flags manually to restore normal access.

## 🛠️ Architecture & Tech Stack

* **Frontend:** HTML5, Tailwind CSS, Vanilla JavaScript (No heavy frameworks, fast rendering).
* **Backend:** Python 3.11, Flask, SQLAlchemy (Async), asyncpg.
* **Database:** PostgreSQL (Designed for Neon.tech Serverless Postgres).
* **Auth & Comms:** Resend API (Transactional Emails), JWT (HS256).
* **Infrastructure:** Docker, Docker Compose, Nginx.

---

## 📂 Database Schema Design
The PostgreSQL database is divided into three isolated schemas:
1. `public`: The real production data (Users, Doctors, Patients, Appointments, Notes).
2. `monitor`: The SIEM tables (Threat Actors, Forensic Ledger, Security Alerts).
3. `shadow_vault`: The honeypot layer. Contains exact structural clones of the `public` tables, pre-seeded with fake data.

---

## 🚀 Getting Started

### Prerequisites
* Docker and Docker Compose (Recommended)
* Python 3.11+ (For local execution)
* A PostgreSQL Database (e.g., [Neon.tech](https://neon.tech))
* A [Resend](https://resend.com) API Key for OTP emails.

### 1. Environment Setup
Create a `.env` file in the root directory and configure the following variables:

```ini
# Database
DATABASE_URL=postgresql+asyncpg://user:password@host/dbname?sslmode=require

# JWT Security
JWT_SECRET_KEY=your_super_secret_random_string
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
OTP_EXPIRE_MINUTES=5

# Email (Resend)
RESEND_API_KEY=re_your_api_key_here
RESEND_FROM=onboarding@resend.dev
SMTP_FROM_NAME=Serenity Psychiatric Care
# Set this to your email during dev to catch all OTPs
TEST_EMAIL_OVERRIDE=your.email@gmail.com 

# Rate Limiting
RATE_LIMIT_REQUESTS=30
RATE_LIMIT_WINDOW_SECONDS=60
MAX_FAILED_LOGINS=5
FLASK_DEBUG=true
PORT=5000
```

### 2. Database Initialization
Execute the provided `db/schema.sql` script against your PostgreSQL instance to create the schemas, tables, triggers, and seed data.

### 3. Running the Application

**Option A: Using Docker (Recommended)**
```bash
docker-compose up --build
```
*The app will be available at `http://localhost:8080`*

**Option B: Running Locally (Without Docker)**
```bash
# Install dependencies
pip install -r requirements.txt

# Run the Flask API
python app.py
```
*Note: If running without Docker, you will need to serve the frontend HTML files manually (e.g., using VS Code Live Server) and configure CORS or a local proxy.*

---

## 🕵️‍♂️ Usage & Testing Guide

### Standard Login
1. Go to `index.html`.
2. Enter a seeded Provider ID (e.g., `DOC-001`) or Patient MRN (e.g., `PT-101`).
3. Check your email (or terminal) for the 6-digit OTP and enter it to access the portal.

### Triggering the Honeypot
1. On the login page, enter a malicious payload as your ID: `' OR 1=1 --`
2. The system will throw an "Invalid ID" error, but your IP is now secretly flagged.
3. Refresh the page and log in normally with `DOC-001` and a valid OTP.
4. You will be silently redirected to the Shadow Vault (`Honeypot/doctor_trap.html`). You will only see fake patients (Eleanor Voss, Marcus Delray).

### Accessing the Hidden SOC Admin Dashboard
1. On the main login page (`index.html`), press **`Ctrl + Shift + F`** to reveal the hidden System Override panel.
2. **Root Identity:** `admin`
3. **MFA Token:** `123admin`
4. Click **Decrypt & Enter**. You can now view the forensic ledger and un-ban trapped IPs.

---

## 🔒 Security Notice
This project is built as an educational demonstration of honeypot mechanics and active defense in web applications. Do not deploy this in a production environment containing real Patient Health Information (PHI) without conducting a comprehensive security audit and ensuring full HIPAA/GDPR compliance.
