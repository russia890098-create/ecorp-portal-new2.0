# E-Corp Employee Portal - CTF Challenge

**Theme:** Mr. Robot  
**Difficulty:** Medium (Multi-stage)  
**Flag Format:** `XPL8{...}`

---

## 📖 Challenge Description

*You've discovered E-Corp's internal employee portal. Intelligence suggests there are multiple security vulnerabilities that could lead to root access. Can you exploit them and retrieve the confidential data?*

*"Hello, friend. Are you in control?"*

**Your mission:** Gain root access and decrypt the flag.

**Starting point:** Login with guest credentials provided on the portal.

---

## 🚀 Quick Start (Local)

### Prerequisites
- Python 3.8+
- pip

### Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Copy env template and fill it in
copy .env.example .env

# Initialize database
python init_db.py

# Run the application
python app.py
```

Visit: `http://localhost:5000`

**Guest credentials:** `guest / guest123`

---

## ☁️ Deployment to Render

### Step 1: Prepare Repository

1. Create a new GitHub repository
2. Upload only the source files. Do not commit `.env`, `uploads/`, `ecorp.db`, `__pycache__/`, or `WALKTHROUGH.md`
3. Commit and push:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin YOUR_REPO_URL
   git push -u origin main
   ```

### Step 2: Deploy on Render

1. Go to [render.com](https://render.com) and sign up/login
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository
4. Configure:
   - **Name:** `ecorp-portal` (or any name)
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt && python init_db.py`
   - **Start Command:** `gunicorn app:app`
   - **Instance Type:** Free

5. **Environment Variables** (Add these):
   ```
   SECRET_KEY=<random session secret>
   FLAG_KEY=<random flag key>
   ROOT_PASSWORD=<random root password>
   DECRYPT_KEY_PART1=<random decrypt part 1>
   DECRYPT_KEY_PART2=<random decrypt part 2>
   DECRYPT_KEY_PART3=<random decrypt part 3>
   FLAG_1=XPL8{group_1_flag}
   FLAG_2=XPL8{group_2_flag}
   FLAG_3=XPL8{group_3_flag}
   FLAG_4=XPL8{group_4_flag}
   FLAG_5=XPL8{group_5_flag}
   DECOY_FLAG=XPL8{fake_flag_i_require_something}
   ```

6. Click **"Create Web Service"**
7. Wait 3-5 minutes for deployment
8. Access your challenge at the provided URL!

### Important Deployment Notes

- Every deploy runs `python init_db.py`, which resets the database and rewrites the encrypted flag file
- The app now fails to start if `SECRET_KEY`, `FLAG_KEY`, `ROOT_PASSWORD`, or any of `FLAG_1..FLAG_5` are missing
- Keep `WALKTHROUGH.md`, `.env`, `uploads/`, and `ecorp.db` out of the player-facing repository

---

## 🎯 Challenge Info

**Objective:** Gain root access and retrieve the flag

**Skills Tested:**
- SQL Injection
- Authentication Bypass
- Path Traversal
- Business Logic Exploitation
- Vulnerability Chaining

**Hint System:**
- No hints initially
- Hints provided after 30 minutes if requested

---

## 📁 File Structure

```
ecorp-portal/
├── app.py              # Main Flask application
├── init_db.py         # Database initialization
├── requirements.txt   # Python dependencies
├── .env              # Configuration (don't commit this!)
├── README.md         # This file
├── WALKTHROUGH.md    # Organizer-only solution guide (do not deploy)
├── templates/
│   └── index.html    # Frontend UI
└── uploads/          # Document storage (auto-generated)
```

---

## 🎮 For Players

**Available Accounts:**
- `guest / guest123` - Start here (Level 1)
- Other accounts exist but credentials must be discovered

**Features:**
- Employee search directory
- Document management system
- Privilege elevation requests
- Two-factor authentication

**Tips:**
- Explore all features
- Pay attention to error messages
- Think like an attacker
- Chain multiple vulnerabilities
- Root access is required for the flag

---

## 🛠️ For Organizers

### Resetting the Challenge

```bash
python init_db.py
```

This will:
- Drop existing database
- Recreate all tables
- Generate fresh sample data
- Reset all user accounts

### Monitoring

Check logs for suspicious activity:
- SQLi attempts
- Multiple failed 2FA
- Privilege escalation requests
- Root access attempts

### Identity-Based Flags

- Root decrypt now requires the `X-CTF-Identity` request header.
- Identity mappings are fixed in code: `elliot`, `whiterose`, `tyrell`, `darlene`, `mrrobot`.
- Each identity returns `FLAG_1` through `FLAG_5` respectively.
- Missing or invalid identity returns `DECOY_FLAG`.
- Root decrypt also requires:
- exact encrypted artifact from Stage 3 (`uploads/private/flag.enc`)
- valid combined decryption key in request body (`key`)
- key is assembled from 3 fragments across different stages/surfaces

### Changing the Flag

Create a local `.env` from `.env.example` and set:
``` 
SECRET_KEY=<new random session secret>
FLAG_KEY=<new random flag key>
ROOT_PASSWORD=<new random root password>
DECRYPT_KEY_PART1=<new random decrypt part 1>
DECRYPT_KEY_PART2=<new random decrypt part 2>
DECRYPT_KEY_PART3=<new random decrypt part 3>
FLAG_1=XPL8{your_group_1_flag}
FLAG_2=XPL8{your_group_2_flag}
FLAG_3=XPL8{your_group_3_flag}
FLAG_4=XPL8{your_group_4_flag}
FLAG_5=XPL8{your_group_5_flag}
```

Then restart the application.

### Difficulty Adjustments

**Make Easier:**
- Reduce 2FA code length
- Give more hints in UI
- Weaken path traversal filters

**Make Harder:**
- Add rate limiting
- Implement proper input validation (but leave intentional flaws)
- Add more red herrings

---

## 🔒 Security Notes

⚠️ **This application is intentionally vulnerable!**

DO NOT use any code from this challenge in production systems.

Vulnerabilities include (but not limited to):
- SQL Injection
- Type juggling in authentication
- Path traversal
- Logic flaws in authorization
- Weak encryption
- Session management issues

---

## 📊 Expected Solve Time

- **Beginner:** 2-4 hours
- **Intermediate:** 45-90 minutes
- **Advanced:** 20-30 minutes

---

## 🎓 Learning Objectives

After completing this challenge, players will understand:

1. **SQL Injection:** How to identify and exploit SQLi vulnerabilities
2. **Auth Bypass:** Type juggling and 2FA weaknesses
3. **Path Traversal:** Filter bypass techniques
4. **Logic Bugs:** Business logic exploitation
5. **Attack Chaining:** Combining multiple vulnerabilities
6. **Privilege Escalation:** Authorization flaw exploitation

---

## 🐛 Troubleshooting

**Issue:** Database not found
- **Solution:** Run `python init_db.py`

**Issue:** Templates not loading
- **Solution:** Ensure `templates/` directory exists

**Issue:** Port already in use
- **Solution:** Change port in `app.py` or kill process on port 5000

**Issue:** Render deployment fails
- **Solution:** Check build logs, ensure all environment variables are set

---

## 📝 Credits

**Challenge Author:** [Your Name]  
**Theme:** Mr. Robot (USA Network)  
**Inspired by:** Real-world web application vulnerabilities

---

## 📄 License

This CTF challenge is for educational purposes only.

---

## 🤝 Support

For questions or issues:
- Review error logs
- Test locally before deploying
- Keep `WALKTHROUGH.md` out of the player-facing deployment

---

**"Control is an illusion. But sometimes, illusions are useful."**

*Good luck, and remember: We are fsociety.*
