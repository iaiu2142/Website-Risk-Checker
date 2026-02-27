# AI Website Risk Checker (Extension)

### This project implements a lightweight hybrid website risk detection system. 
### The system performs real-time webpage analysis using heuristic security signals and malicious intent indicators. It evaluates website content, infrastructure characteristics, and suspicious scripting patterns to estimate a risk score.
---
<img width="391" height="318" alt="image" src="https://github.com/user-attachments/assets/63dbc43c-6546-462d-a283-a53c0e7e1746" />
<img width="326" height="286" alt="image" src="https://github.com/user-attachments/assets/d0bb7f6b-388f-49fa-9314-c9147f82311a" />
<img width="343" height="302" alt="image" src="https://github.com/user-attachments/assets/6e1fc01c-4704-47e0-8803-a2f33b71e329" />

---
## 🔍 Features:

### 1️⃣ Content-Based Detection
- Prompt injection indicators
- Privilege escalation language
- Exploit terminology
- Phishing-related keywords

### 2️⃣ Infrastructure-Level Heuristics
- HTTP error page detection (503, 500, 502)
- HTTPS validation
- IP-based URL detection
- Suspicious domain structure analysis

### 3️⃣ Hidden & Obfuscated Malware Signals
- Suspicious script patterns (eval, atob, unescape)
- Long Base64-encoded strings (possible obfuscation)
- Hidden iframe detection

---
## ⚙️ Risk Classification Logic

The system computes a normalized risk score (0–100%) based on detected signals.

| Risk Score | Classification |
|------------|---------------|
| 0–25%      | Safe          |
| 25–50%     | Suspicious    |
| 50%+       | Malicious     |

---
## Installation

1. Download the repository as ZIP.
2. Extract the folder.
3. Open Chrome and go to: chrome://extensions/
4. Enable Developer Mode.
5. Click Load Unpacked.
6. Select the extracted folder.

## Usage

Click the extension icon and scan any website.
