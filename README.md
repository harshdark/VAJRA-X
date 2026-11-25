# VAJRA-X v0.1

A small, non-destructive web security posture assessment mini-project.

## Features

- URL normalization and public DNS resolution
- Blocks private, loopback, link-local and reserved IP destinations
- DNS record lookup (A, AAAA, MX, NS, TXT)
- TLS certificate metadata and verification
- HTTP security-header checks
- Basic cookie-flag observations
- Lightweight technology indicators
- Passive Certificate Transparency subdomain lookup via crt.sh
- Heuristic risk summary
- JSON report download

## Important limitations

This is an educational MVP, not a complete penetration-testing platform and not proof that a target is secure. It does not exploit vulnerabilities, brute-force credentials, bypass a WAF/CDN, perform load testing, or create a faithful copy of a production application.

A URL alone cannot reveal or reproduce private backend code, databases, authentication logic, cloud configuration, endpoint telemetry, or network controls. Those require owner-provided test assets and a properly isolated lab.

## Authorization and safe use

Use only on websites you own or have explicit written permission to assess. The app makes a small number of DNS lookups and ordinary HTTP GET requests. It blocks destinations resolving to non-public IP addresses and re-validates redirect destinations. Do not use it against systems outside your authorized scope.

## Setup (Windows)

1. Install Python 3.10 or newer.
2. Extract this project.
3. Open PowerShell in the project folder.
4. Create and activate a virtual environment:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

5. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

6. Run:

```powershell
streamlit run app.py
```

The app opens in your browser, usually at `http://localhost:8501`.

## Setup (Linux / Kali / Parrot)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

## Project structure

```text
vajra_x_v0_1/
├── app.py
├── requirements.txt
├── README.md
└── vajra/
    ├── __init__.py
    ├── safety.py
    └── scanner.py
```

## Suggested demo

Use a domain you own or a deliberately vulnerable training application hosted in a lab that you control. Capture screenshots of:
- DNS results
- TLS certificate details
- HTTP response and security headers
- Findings and recommendations
- Downloaded JSON report

## Future roadmap

- v0.2: authenticated testing using owner-provided test accounts and API specifications
- v0.3: isolated digital-twin lab for supported applications
- v0.4: safe adversary-behaviour simulations and telemetry comparison
- v1.0: modular security validation platform with evidence-backed results


ALTERNATIVE IF ABOVE CODE NOT RUN 

## Setup (Windows)

1. Install Python 3.10 or newer.
2. Extract this project.
3. Open CMD or PowerShell in the project folder.
4. Create a virtual environment:

```cmd
py -m venv .venv
```

5. Activate the virtual environment (optional):

**CMD:**
```cmd
.venv\Scripts\activate.bat
```

**PowerShell:**
```powershell
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can skip activation and use the virtual environment's Python directly:

```cmd
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

6. Install dependencies:

```cmd
python -m pip install -r requirements.txt
```

7. Run the application:

```cmd
streamlit run app.py
```

The app opens in your browser, usually at http://localhost:8501.
