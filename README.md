# 🔐 Secure Key Management System

This project is a **two-part secure key management system** designed to protect secrets even in the case of a compromised server. It uses **asymmetric encryption**, **JWT-based authorization**, and strict role separation between two services:

- **App A: Master Key Manager** – Responsible for encrypting user-submitted secrets and issuing signed access tokens.
- **App B: Encrypted Key Vault** – Responsible for storing encrypted secrets and only decrypting them if a valid signed token is presented.

---

## ⚙️ Technologies Used
- Python 3.x
- Flask
- `cryptography` library
- `PyJWT` (JWT encoding/decoding)
- RSA encryption

---

## 📦 Directory Structure
```
.
├── app_a.py               # App A - Master Key Manager
├── app_b.py               # App B - Secure Vault
├── app_a_private.pem      # App A's RSA private key (for signing tokens)
├── app_a_public.pem       # App A's RSA public key
├── app_b_private.pem      # App B's RSA private key (for decrypting data)
├── app_b_public.pem       # App B's RSA public key (used by App A to encrypt data)
├── README.md              # This file
```

---

## 🔧 Setup Instructions

### 1. 📥 Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install flask cryptography pyjwt requests
```

### 2. 🔑 Generate RSA Keys

#### For App A (Token Signing)
```bash
openssl genpkey -algorithm RSA -out app_a_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in app_a_private.pem -out app_a_public.pem
```

#### For App B (Key Encryption/Decryption)
```bash
openssl genpkey -algorithm RSA -out app_b_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in app_b_private.pem -out app_b_public.pem
```

### 3. 🚀 Run the Applications
```bash
# Terminal 1
python app_b.py  # Runs on port 8001

# Terminal 2
python app_a.py  # Runs on port 8000
```

---

## 🔁 Usage Workflow

### 🔐 Step 1: Store a Secret via App A
**POST** `http://localhost:8000/api/keys`
```json
{
  "user_id": "user123",
  "key_data": "super_secret_value"
}
```
📥 **Response:**
```json
{
  "message": "Key stored successfully",
  "access_token": "<JWT>"
}
```

### 🔓 Step 2: Retrieve the Secret via App B
**GET** `http://localhost:8001/api/keys/<key_id>`
```
Authorization: Bearer <JWT>
```
📤 **Response:**
```json
{
  "decrypted_key": "super_secret_value"
}
```

---

## ✅ Security Features
- 🔐 **RSA Encryption** (2048-bit) for secure key wrapping
- 🔏 **JWT-based access tokens** signed by App A
- 🔑 **Token validation and decryption** only by App B
- 🔄 **Separation of concerns**: App A never stores secrets, App B never generates tokens

---

## 🧪 Optional Enhancements
- Use **AES key wrapping** for faster encryption
- Add **SQLite/PostgreSQL** backend for persistence
- Enable **token blacklisting and revocation**
- Integrate **HSMs or cloud KMS services** (e.g., AWS KMS)

---

## 📄 License
MIT License

---

## 🙋 Need Help?
Open an issue or request implementation help in other stacks like **Node.js**, **Go**, or **Docker Compose**!
