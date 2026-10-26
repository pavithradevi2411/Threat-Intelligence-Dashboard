# Threat Intelligence Dashboard

## Overview

The Threat Intelligence Dashboard is a Python-based cybersecurity project that helps users investigate IP addresses and URLs using the VirusTotal API. It presents threat analysis results through a web dashboard and generates PDF reports for further review.

## Features

* IP address investigation
* URL investigation
* VirusTotal API integration
* Threat severity classification
* Malicious, suspicious, harmless, and undetected detection counts
* Investigation history stored in SQLite
* Dashboard statistics and charts
* PDF report generation and download
* Environment variables for API key configuration

## Technologies Used

* Python
* Flask
* VirusTotal API v3
* SQLite
* HTML and CSS
* JavaScript and Chart.js
* ReportLab
* Requests
* python-dotenv

## Project Structure

```text
Threat_Intelligence_Dashboard/
├── templates/
│   └── dashboard.html
├── app.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/pavithradevi2411/Threat-Intelligence-Dashboard.git
cd Threat-Intelligence-Dashboard
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure the VirusTotal API key

Create a `.env` file in the project root directory and add:

```text
VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY
```

Replace the placeholder with your own VirusTotal API key. Never upload your `.env` file to GitHub.

### 5. Run the application

```bash
python app.py
```

Open your browser and visit:

http://127.0.0.1:5000/

## How It Works

1. The user submits an IP address or URL.
2. The application sends a request to the VirusTotal API.
3. The application processes the returned analysis data.
4. The dashboard displays the detection counts and severity classification.
5. Investigation results are stored in a local SQLite database.
6. Users can download PDF reports of their investigations.

## Security Notes

* Keep API keys private.
* Do not commit `.env` files or local databases.
* Use threat intelligence results as indicators for investigation, not as conclusive proof of malicious activity.
* Respect VirusTotal API usage limits.

## Author

Cybersecurity Project — Threat Intelligence Dashboard
