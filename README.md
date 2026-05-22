# 🛡 ShieldScan – Predictive Security Health Scoring for Smartphones

Real-time smartphone security analysis system using Android Debug Bridge (ADB) and predictive risk scoring.

ShieldScan extracts live Android device telemetry and evaluates the device's security posture by analyzing critical parameters such as OS version, screen lock status, unknown app installation settings, permissions, sideloaded apps, developer options, and more.

The system computes a security score and highlights active vulnerabilities with a modern Streamlit dashboard.

---

## Features

✅ Real-time Android device monitoring through ADB

✅ Security health score generation

✅ Detect outdated Android versions

✅ Detect unknown source installations

✅ Analyze dangerous permissions

✅ Detect sideloaded applications

✅ Monitor USB debugging and developer settings

✅ Risk categorization system

✅ Live dashboard with visual analytics

---

## Technologies Used

- Python
- Streamlit
- Android Debug Bridge (ADB)
- Pandas
- Regex
- Real-time Device Telemetry

---

## Project Workflow

1. Connect Android device using USB

2. Enable Developer Options

3. Enable USB Debugging

4. Authorize ADB access

5. Run the application

6. Device information is extracted

7. Security score is calculated

8. Dashboard displays risks and recommendations

---

## Installation

Clone repository:

```bash
git clone https://github.com/yourusername/ShieldScan-Security-Health.git
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run project:

```bash
streamlit run app.py
```

---

## How It Works

The system collects:

- Android OS version
- Screen lock status
- Dangerous app permissions
- Unknown app settings
- Sideloaded applications
- Security patch version
- Bluetooth status
- Encryption status
- USB debugging state

These parameters are processed through a predictive scoring engine to generate a device security health score.

---

## Example Output

Security Score: 82/100

Status: GOOD

Detected Risks:

- USB debugging enabled
- Outdated security patch
- Bluetooth active

---

## Future Improvements

- Machine learning based malware prediction
- Historical device monitoring
- Cloud storage support
- Multiple device comparison
- PDF report generation

---

## Author

Kishore G
