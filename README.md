Here’s a well-structured `README.md` file tailored for your `app.py` — a secure data vault built with Streamlit and Python:

---

```markdown
# 🔐 Secure Vault Web App

A secure, password-protected data vault web application built using **Streamlit**, enabling users to:
- Register and log in securely
- Store and retrieve sensitive information
- Encrypt/decrypt data with user-defined keys
- Prevent brute-force attacks with login throttling
- Ensure data confidentiality with AES encryption (Fernet)

---

## 🚀 Features

- 🔐 **User Authentication** with password hashing (PBKDF2 + SHA256)
- 🧠 **Strong Encryption** using Fernet symmetric cryptography
- 📁 **Encrypted Data Vault** for each user
- 🕒 **Session Management** with timeouts and activity tracking
- 🔐 **Brute-force Protection** with lockout after 3 failed login attempts
- 💡 **Clean Streamlit UI** with tabs for login/register and sidebar navigation
- 🌘 **Dark mode compatible** (via Streamlit theme settings)

---

## 📂 Project Structure

```bash
.
├── app.py                # Main Streamlit app
├── secure_data/          # Encrypted data and salt storage
│   ├── salt.key
│   └── vault.json
└── README.md
└── requirements.txt             # necessary dependencies
```

---

## 🛠️ Installation

Make sure you have **Python 3.8+** installed.

### 1. Clone this repo

```bash
git clone https://github.com/usama7871/Assignment-05.git
```

### 2. Create a virtual environment (optional but recommended)

```bash
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> Example `requirements.txt`:

```
streamlit
cryptography
```

---

## 🧪 Running the App

```bash
streamlit run app.py
```

Access the app in your browser at `http://localhost:8501`.

---

## 🛡️ Security Overview

- **Encryption**: AES (Fernet) using keys derived via PBKDF2-HMAC with 100,000 iterations
- **Password Hashing**: Secure SHA256 with salt
- **Storage**: Encrypted JSON vault in `secure_data/vault.json`
- **Lockout Mechanism**: After 3 failed attempts, login is disabled for 5 minutes
- **Session Timeout**: Auto logout after 10 minutes of inactivity

---

## 🧠 Use Case

Perfect for:
- Developers learning about cryptography and secure apps
- Medical or research professionals protecting sensitive notes
- Personal journal/vault with strong encryption

---

## 🧑‍💻 Author

**Usama**  
3rd Year MBBS (ex), aspiring AI/ML and software engineer.  
Interested in medical technology, AI for healthcare, and secure software systems.  

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

```
