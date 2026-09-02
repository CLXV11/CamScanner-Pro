
```markdown
# 📸 CamScanner-Pro v2.1

<div align="center">

**Professional IP Camera Security Audit Framework | Termux for Android**

⚠️ **For Personal Devices Only** ⚠️

</div>

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 🔍 **Smart Fingerprint** | Auto-detect vendor & model via headers |
| 💣 **Real CVEs** | CVE-2017-7921/7925 (Hikvision) + CVE-2021-33044 (Dahua) |
| 📸 **RTSP Capture** | Auto-grab I-frame from open streams |
| 🌐 **Shodan Search** | Global exposed camera search via API |
| 📊 **JSON Export** | Structured output for tool integration |
| 🔐 **Credential Test** | Default & weak password detection |

---

## 📥 Installation

```bash
# Clone repo
git clone https://github.com/CLXV11/CamScanner-Pro.git
cd CamScanner-Pro

# Make executable
chmod +x camsec_pro.sh

# Run
./camsec_pro.sh

# First time: choose 6 to install dependencies
```

---

🖥️ Usage

```bash
./camsec_pro.sh
```

# Option
1 Full Audit (discover + scan)
2 Single Target Scan
3 Fingerprint Only
4 Vulnerability Scan
5 Credential Test
6 Install Dependencies
7 Configure Shodan
8 Shodan Search

---

💣 Supported CVEs

CVE Vendor Severity
CVE-2017-7921 Hikvision 🔴 Critical
CVE-2017-7925 Hikvision 🔴 Critical
CVE-2021-33044 Dahua 🔴 Critical

---

🔧 Requirements

· Termux (from F-Droid)
· Android 7.0+
· 500MB free storage

---

📁 Output

```
.camsec/
├── captures/   ← RTSP screenshots
├── reports/    ← JSON reports
└── logs/       ← Log files
```

---

⚠️ Disclaimer

This tool is for educational purposes and testing YOUR OWN devices only.
Unauthorized use is a cybercrime.

---

<div align="center">

⭐ Star this repo if you find it useful

</div>
```

---

Quick Install (Copy-Paste to Termux)

```bash
git clone https://github.com/CLXV11/CamScanner-Pro.git && cd CamScanner-Pro && chmod +x camsec_pro.sh && ./camsec_pro.sh
```
