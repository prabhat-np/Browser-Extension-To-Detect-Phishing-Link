# Design and Development of an AI-Driven Phishing Link Detection, Risk Assessment, and Cybersecurity Awareness Platform for the Banking Sector in Kathmandu Valley

**Final Year Project (FYP) Submission**

---

## 📘 1. Academic Abstract
The banking sector in Kathmandu Valley is undergoing a rapid digital transformation, which has inadvertently expanded the attack surface for cybercriminals. Phishing attacks, specifically Business Email Compromise (BEC) and deceptive URL spoofing, have emerged as the primary vector for financial fraud in Nepal. Traditional signature-based detection systems are increasingly ineffective against zero-day phishing campaigns that utilize sophisticated obfuscation techniques. This project addresses this critical gap by developing **FinShield AI**, a comprehensive cybersecurity platform that integrates Machine Learning for real-time threat detection with a dedicated module for employee security awareness.

The proposed system utilizes a Random Forest classifier to analyze over 20 lexical and host-based URL features, providing a probabilistic risk assessment rather than a binary classification. By automating the detection process, FinShield AI significantly reduces the response time for Security Operations Centers (SOCs). Furthermore, recognizing that the "human element" is often the weakest link in cybersecurity, the platform includes an interactive training module designed to educate bank employees on identifying social engineering tactics. This dual approach—technological defense combined with human capacity building—offers a holistic security posture for financial institutions.

It is important to note that **FinShield AI** is designed as a decision-support system. While it achieves high accuracy in detecting malicious patterns, it is intended to augment, not replace, human security analysts. The system provides confidence scores and feature-based explainability (XAI) to assist experts in making informed decisions regarding potential threats.

---

## 🚀 2. Product Overview: FinShield AI
**FinShield AI** is a commercial-grade cybersecurity SaaS product tailored for the banking industry. It is designed to be deployed within a bank's secure intranet or private cloud infrastructure.

### 🏦 Real-World Use Cases
*   **Security Operations Center (SOC)**: Analysts use the **Threat Scanner** and **Batch Processing** tools to audit incoming emails and flagged URLs.
*   **Employee Onboarding**: HR departments use the **Training Center** to certify new hires on cybersecurity best practices before granting system access.
*   **Compliance Audits**: Risk Managers generate **PDF Reports** to demonstrate compliance with Nepal Rastra Bank's IT guidelines.

### 💰 Deployment & Licensing Model
*   **Deployment**: On-Premise (Air-gapped servers) for maximum security, or Private Cloud (AWS/Azure) for scalability.
*   **Licensing**: Per-Seat licensing for the Training Module, and Per-Core licensing for the Threat Detection Engine.

---

## 🏗️ 3. System Architecture
The system follows a modular microservices-ready architecture:
1.  **Core Engine (`core/`)**: Handles feature extraction and ML inference.
2.  **Auth Service (`services/`)**: Manages JWT tokens, Cookie persistence, and Role-Based Access Control (RBAC).
3.  **Training Service (`services/`)**: Manages quiz content, user progress, and scoring logic.
4.  **Presentation Layer (`web/`)**: A responsive Streamlit dashboard with a custom Banking-Grade UI theme.

---

## 🛠️ 4. Installation & Setup

### Prerequisites
*   Python 3.8+
*   Pip package manager

### Step 1: Install Dependencies
Open your terminal in the project root and run:
```bash
pip install -r requirements.txt
```

### Step 2: Run the System
Execute the automated launcher script:
```bash
python run_app.py
```
*The system will automatically train the model (if missing) and launch the web interface at `http://localhost:8501`.*

---

## 🔐 5. Default Credentials (For Demo/Viva)
Use the following credentials to demonstrate different roles:

| Role | Username | Password | Capabilities |
|------|----------|----------|--------------|
| **Administrator** | `admin` | `admin123` | Full Access, Model Retraining, User Audits, Training Analytics |
| **Analyst** | `analyst` | `analyst123` | Batch CSV Scanning, PDF Reporting |
| **Employee** | `employee` | `employee123` | Training Modules, Quizzes, Certificates |
| **Viewer** | `viewer` | `viewer123` | Single URL Scan, Dashboard View |

---

## 🖥️ 6. Demo Walkthrough Guide

1.  **Login Persistence**: Log in as `admin`. Close the tab and reopen it. Show that you remain logged in (Cookie Persistence).
2.  **Dashboard**: Explain the "Weekly Threat Landscape" charts and KPI metrics.
3.  **Threat Scanner**:
    *   Enter a safe URL (e.g., `https://google.com`). Show "Low Risk".
    *   Enter a phishing URL (e.g., `http://secure-login-apple.com`). Show "High Risk" & Explainability features.
4.  **Batch Processing**: Switch to `analyst` account. Upload a dummy CSV to show bulk scanning.
5.  **Training Module**: Switch to `employee` account. Take the "Phishing Basics" quiz. Show the score and "Pass" status.
6.  **Admin Analytics**: Switch back to `admin`. Go to "Admin Panel" -> "Employee Performance" to show the employee's quiz result.

---

## ⚠️ 7. Limitations & Future Scope
*   **Scope**: Currently analyzes URL lexical/host features. Does not download webpage content (HTML/Images) to avoid sandbox risks.
*   **Future Work**: Integration of Computer Vision to detect visual brand impersonation (e.g., fake logos).

---
*Submitted by Prabhat*
