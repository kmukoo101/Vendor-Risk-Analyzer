"""
A Supply Chain Cybersecurity Risk Scanning Tool with GUI and Export

"""

import os
import json
import socket
import logging
import requests
import ssl
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from urllib.parse import urlparse
from typing import List, Dict
from fpdf import FPDF

# --- API KEYS from environment ---
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

# --- Setup Logging ---
LOG_FILE = "vendor_risk_analyzer.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Constants ---
VENDOR_INPUT_FILE = "vendors.json"

# --- Risk scoring weights ---
RISK_WEIGHTS = {
    "expired_ssl": 25,
    "no_https": 20,
    "exposed_ports": 15,
    "breach_found": 30,
    "domain_age_low": 10,
    "shodan_critical": 40,
    "hibp_breach": 20,
    "ip_reputation_bad": 15
}

# Container for report results
scan_report = {}

def load_vendors(filepath: str) -> List[Dict]:
    """Load vendors from a JSON file.

    Args:
        filepath (str): Path to the vendor input file.

    Returns:
        List[Dict]: List of vendor dictionaries.
    """
    try:
        with open(filepath, 'r') as file:
            return json.load(file)
    except Exception as e:
        logging.error(f"Failed to load vendor file: {e}")
        return []

def check_https(domain: str) -> bool:
    """Check if a domain supports HTTPS.

    Returns True if HTTPS is working and returns status 200.
    """
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return response.status_code == 200
    except Exception:
        return False

def check_ssl_expiration(domain: str) -> bool:
    """Determine whether a domain's SSL certificate is expired.

    Returns True if expired, or False if valid.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return expiry < datetime.datetime.utcnow()
    except Exception:
        return True  # Default to expired if check fails

def check_domain_age(domain: str) -> bool:
    """Check whether domain age is less than 1 year old.

    Returns True if domain is considered 'young'.
    """
    try:
        response = requests.get(f"https://api.domaintools.com/v1/{domain}/whois")
        if response.status_code == 200:
            data = response.json()
            created_date = data.get("created")
            if created_date:
                created = datetime.datetime.strptime(created_date, "%Y-%m-%d")
                return (datetime.datetime.utcnow() - created).days < 365
        return False
    except Exception:
        return False

def check_data_breach(domain: str) -> bool:
    """Simulated manual check for known breached domains (placeholder).

    Replace with real logic or list for actual breach tracking.
    """
    return domain in ["examplebreached.com", "riskyvendor.io"]

def check_email_breach(email: str) -> bool:
    """Query HaveIBeenPwned to check if an email has been in breaches.

    Returns True if the email is found in any breach.
    """
    if not HIBP_API_KEY:
        return False
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": HIBP_API_KEY,
            "User-Agent": "CVEye Risk Analyzer"
        }
        response = requests.get(url, headers=headers, timeout=10)
        return response.status_code == 200 and response.json() != []
    except Exception as e:
        logging.warning(f"HIBP error for {email}: {e}")
        return False

def check_ip_reputation(ip: str) -> str:
    """Check IP address threat level using IPInfo.io.

    Returns string such as 'high', 'medium', 'low', or 'unknown'.
    """
    if not IPINFO_TOKEN:
        return "Unknown"
    try:
        url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("abuse", {}).get("threat", "Unknown")
        return "Unknown"
    except Exception as e:
        logging.warning(f"IP reputation check failed for {ip}: {e}")
        return "Unknown"

def shodan_scan(domain: str) -> Dict:
    """Use Shodan to check for exposed ports or tags.

    Returns dict with open ports, critical exposure flag, and IP.
    """
    if not SHODAN_API_KEY:
        return {"open_ports": [], "critical_exposure": False, "ip": ""}
    try:
        ip = socket.gethostbyname(domain)
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            ports = data.get("ports", [])
            tags = data.get("tags", [])
            critical = any(t in tags for t in ["malware", "compromised", "vulnerable"])
            return {"open_ports": ports, "critical_exposure": critical, "ip": ip}
        return {"open_ports": [], "critical_exposure": False, "ip": ip}
    except Exception as e:
        logging.error(f"Shodan scan failed for {domain}: {e}")
        return {"open_ports": [], "critical_exposure": False, "ip": ""}

def calculate_risk_score(domain: str, email: str = "") -> Dict:
    """Perform full risk calculation for a domain/email.

    Combines multiple checks and returns risk data dictionary.
    """
    score = 0
    results = {}

    results["https_enabled"] = check_https(domain)
    if not results["https_enabled"]:
        score += RISK_WEIGHTS["no_https"]

    results["ssl_expired"] = check_ssl_expiration(domain)
    if results["ssl_expired"]:
        score += RISK_WEIGHTS["expired_ssl"]

    results["breach_found"] = check_data_breach(domain)
    if results["breach_found"]:
        score += RISK_WEIGHTS["breach_found"]

    results["domain_age_low"] = check_domain_age(domain)
    if results["domain_age_low"]:
        score += RISK_WEIGHTS["domain_age_low"]

    shodan_results = shodan_scan(domain)
    results["shodan"] = shodan_results
    if shodan_results.get("critical_exposure"):
        score += RISK_WEIGHTS["shodan_critical"]

    if email:
        results["email_breached"] = check_email_breach(email)
        if results["email_breached"]:
            score += RISK_WEIGHTS["hibp_breach"]

    ip = shodan_results.get("ip")
    if ip:
        threat_level = check_ip_reputation(ip)
        results["ip_reputation"] = threat_level
        if threat_level.lower() in ["high", "critical"]:
            score += RISK_WEIGHTS["ip_reputation_bad"]

    results["final_score"] = score
    results["risk_level"] = (
        "High" if score >= 60 else
        "Medium" if score >= 30 else
        "Low"
    )

    return results

def analyze_all_vendors():
    """Main analysis loop for all vendors in the input file.

    Updates the global scan_report dict with results.
    """
    vendors = load_vendors(VENDOR_INPUT_FILE)
    if not vendors:
        print("No vendor data found.")
        return {}

    report = {}
    for vendor in vendors:
        domain = urlparse(vendor.get("domain", "")).netloc or vendor.get("domain", "")
        email = vendor.get("contact_email", "")
        print(f"Analyzing {vendor.get('name')} ({domain})...")
        logging.info(f"Analyzing {vendor.get('name')} at {domain}")
        scorecard = calculate_risk_score(domain, email)
        report[vendor.get("name")] = {
            "domain": domain,
            "scorecard": scorecard,
            "contact_email": email
        }

    global scan_report
    scan_report = report
    return report
