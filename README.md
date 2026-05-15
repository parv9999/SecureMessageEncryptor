# 🔐 Secure Message Encryption System

A cloud-deployable cybersecurity application designed for secure communication using modern cryptographic techniques, QR-based encrypted data sharing, and real-time decryption workflows.

---

# 🚀 Project Overview# 🔐 Secure Message Encryption System

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Cryptography](https://img.shields.io/badge/Fernet-AES%20Encryption-4B8BBE?style=for-the-badge&logo=letsencrypt&logoColor=white)](https://cryptography.io/)
[![OpenCV](https://img.shields.io/badge/OpenCV-QR%20Scanning-5C3EE8?style=for-the-badge&logo=opencv&logoColor=white)](https://opencv.org/)
[![Render](https://img.shields.io/badge/Render-Cloud%20Deploy-46E3B7?style=for-the-badge&logo=render&logoColor=white)](https://render.com/)

> A cloud-deployable cybersecurity application for **end-to-end encrypted messaging** using Fernet AES symmetric encryption, QR-based secure data transfer, and real-time decryption — served via an interactive Streamlit interface.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Core Features](#core-features)
- [System Workflow](#system-workflow)
- [Cybersecurity Concepts](#cybersecurity-concepts-implemented)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Potential Applications](#potential-applications)
- [Author](#author)

---

## 📖 Overview

The **Secure Message Encryption System** enables users to encrypt confidential messages using **Fernet AES symmetric encryption**, encode them into downloadable QR codes for secure sharing, and instantly decrypt them by scanning or uploading a QR image — all through a clean Streamlit web interface.

| Capability | Details |
|---|---|
| 🔒 Encryption | Fernet AES symmetric cipher |
| 📤 Secure Sharing | Encrypted message encoded into QR code |
| 📥 Decryption | QR upload → automatic decode → original message |
| 🔑 Key Management | Secret key generation, storage & lifecycle handling |
| 🔐 Auth Layer | Password-protected decryption workflow |
| 🌐 Interface | Real-time Streamlit web app |
| ☁️ Deployment | Cloud-deployable via Render (`render.yaml` included) |

---

## ✨ Core Features

- 🔐 **AES Encryption** — Fernet-based symmetric key encryption for all messages
- 🔑 **Secure Key Generation** — Auto-generated secret keys with safe storage
- 🛡️ **Password-Protected Decryption** — Auth layer before message reveal
- 📷 **QR Code Generation** — Encrypted ciphertext encoded as a scannable QR image
- 📤 **Downloadable QR** — Save & share encrypted QR codes as `.png` files
- 📥 **QR Upload & Auto-Decode** — Upload a QR image for instant decryption
- ⚡ **Real-Time Interface** — Streamlit-powered live web UI
- ☁️ **Cloud Ready** — Render deployment config included out of the box

---

## 🔄 System Workflow

```
  User Enters Message
          ↓
  ┌───────────────────┐
  │   AES Encryption  │  ← Fernet symmetric key
  └────────┬──────────┘
           │
  Encrypted Ciphertext
           │
  ┌───────────────────┐
  │ QR Code Generation│  ← qrcode library
  └────────┬──────────┘
           │
  Downloadable encrypted_qr.png
           │
     Secure Sharing
           │
  ┌───────────────────┐
  │  QR Upload / Scan │  ← pyzbar + OpenCV
  └────────┬──────────┘
           │
  Password Authentication
           │
  ┌───────────────────┐
  │  AES Decryption   │  ← Fernet key lookup
  └────────┬──────────┘
           │
  ✅ Original Message Revealed
```

---

## 🧠 Cybersecurity Concepts Implemented

| Concept | Implementation |
|---|---|
| Symmetric Key Encryption | Fernet AES cipher (cryptography library) |
| Secure Key Lifecycle | Key generation, storage & scoped access |
| QR-Based Data Transport | Encrypted ciphertext embedded in QR codes |
| Password Authentication | Gate before decryption workflow |
| Secure Message Exchange | End-to-end encrypted communication |
| Privacy-Oriented Design | No plaintext stored or transmitted |

---

## 🛠️ Tech Stack

| Category | Tools |
|---|---|
| **Language** | Python |
| **Web Interface** | Streamlit |
| **Encryption** | cryptography (Fernet AES) |
| **QR Generation** | qrcode |
| **QR Scanning** | pyzbar, OpenCV |
| **Image Processing** | Pillow (PIL) |
| **Cloud Deployment** | Render (`render.yaml`) |

---

## 📁 Project Structure

```
SecureMessageEncryptor/
│
├── main.py                # Streamlit app — main entry point
├── encryption.py          # Fernet AES message encryption logic
├── decryption.py          # Fernet AES message decryption logic
├── generate_key.py        # Secret key generation & management
├── qr_generator.py        # QR code creation from ciphertext
│
├── encrypted_qr.png       # Sample generated encrypted QR output
├── secret.key             # Stored symmetric encryption key
│
├── render.yaml            # Render cloud deployment config
├── requirements.txt       # Python dependencies
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- pip

### 1. Clone the Repository

```bash
git clone https://github.com/parv9999/SecureMessageEncryptor.git
cd SecureMessageEncryptor
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Key packages installed:

```
streamlit
cryptography
qrcode
pyzbar
opencv-python
Pillow
```

### 3. Generate a Secret Key

```bash
python generate_key.py
```

> This creates a `secret.key` file used for all encryption/decryption. **Keep this file safe — losing it means losing access to all encrypted messages.**

### 4. Run the Application

```bash
streamlit run main.py
```

Visit `http://localhost:8501` in your browser.

---

### ☁️ Deploy on Render

This project includes a `render.yaml` config for one-click cloud deployment:

1. Push your repo to GitHub
2. Go to [render.com](https://render.com) → **New Web Service**
3. Connect your GitHub repo
4. Render auto-detects `render.yaml` and deploys

---

## 💡 Potential Applications

- 🏢 Secure enterprise communication systems
- 📦 Encrypted QR-based document/data transfer
- 🎓 Cybersecurity education & live demonstrations
- 💬 Privacy-focused messaging platforms
- 🔏 Secure credential or token sharing

---

## 📌 Key Highlights

- Designed a full end-to-end encryption workflow from plaintext → ciphertext → QR → decrypt
- Integrated AES encryption with QR-based physical/digital transport mechanisms
- Implemented real-time QR scanning and decryption via OpenCV and pyzbar
- Built an accessible Streamlit frontend requiring zero frontend development overhead
- Applied production cybersecurity practices: key lifecycle management, auth-gated decryption, no plaintext persistence

---

## 👤 Author

**Parv Chauhan**
B.Tech CSE — Cloud Computing Specialization
VIT Bhopal University

- GitHub: [@parv9999](https://github.com/parv9999)
- Email: [parvchauhan36@gmail.com](mailto:parvchauhan36@gmail.com)

---

<p align="center">🔐 Encrypt everything. Trust nothing. Share safely.</p>

The Secure Message Encryption System is a Python-based web application that enables users to securely encrypt, share, and decrypt confidential messages using **Fernet AES symmetric encryption**. The platform integrates QR code technology for secure encrypted message transfer and provides a streamlined interface for encryption workflows through Streamlit.

The project emphasizes practical cybersecurity implementation, secure key handling, encrypted communication, and privacy-focused application development.

---

# ✨ Core Features

* Secure message encryption and decryption
* Fernet AES-based symmetric cryptography
* Password-protected decryption workflow
* QR code generation for encrypted messages
* QR image upload and automatic decoding
* Secure secret key generation and management
* Downloadable encrypted QR codes
* Real-time Streamlit web interface
* Lightweight and deployable architecture

---

# 🛠 Technologies Used

### Programming & Frameworks

* Python
* Streamlit

### Cybersecurity & Encryption

* Cryptography Library (Fernet AES)

### QR Processing

* qrcode
* pyzbar
* OpenCV

### Additional Libraries

* Pillow (PIL)

---

# 📁 Project Structure

```
SecureMessageEncryptor/
├── main.py
├── encryption.py
├── decryption.py
├── generate_key.py
├── qr_generator.py
├── encrypted_qr.png
├── secret.key
├── requirements.txt
├── render.yaml
└── README.md
```

---

# 🔒 System Workflow

```
User Message
     ↓
AES Encryption
     ↓
Encrypted Cipher Text
     ↓
QR Code Generation
     ↓
Secure Sharing
     ↓
QR Upload/Scan
     ↓
Automatic Decryption
     ↓
Original Message
```

---

# ▶️ Installation & Setup

## Clone Repository

```
git clone https://github.com/parv9999/SecureMessageEncryptor.git

cd SecureMessageEncryptor
```

## Install Dependencies

```
pip install -r requirements.txt
```

## Run Application

```
streamlit run main.py
```

---

# 🧠 Cybersecurity Concepts Implemented

* Symmetric Key Encryption
* Fernet AES Cryptography
* Secure Key Lifecycle Management
* QR-Based Secure Data Transmission
* Password Authentication
* Secure Message Exchange
* Privacy-Oriented Application Design

---

# 💡 Potential Applications

* Secure enterprise communication
* Encrypted QR-based information exchange
* Cybersecurity education & demonstrations
* Privacy-focused messaging platforms
* Secure document transfer systems

---

# 📌 Key Highlights

* Designed a secure end-to-end encryption workflow
* Integrated encryption with QR-based transport mechanisms
* Implemented real-time decryption and QR scanning capabilities
* Built an interactive Streamlit-based frontend for accessibility
* Applied practical cybersecurity and secure communication principles

---

# 👨‍💻 Author

Parv Chauhan
B.Tech CSE (Cloud Computing)
VIT Bhopal University
