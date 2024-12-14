import streamlit as st
import requests
from urllib.parse import urlencode

# Predefined constants for banks and domains
BANK_LIST = ["HDFC Bank", "ICICI Bank", "Axis Bank", "IndusInd Bank", "State Bank of India (SBI)"]
DOMAIN_MAP = {
    "HDFC Bank": "hdfcbank.com",
    "ICICI Bank": "icicibank.com",
    "Axis Bank": "axisbank.com",
    "IndusInd Bank": "indusind.com",
    "State Bank of India (SBI)": "onlinesbi.com",
}

# API keys for external services
API_KEY_WHOXY = "622c4c22df6f04cehc26db76c8c603a47"
API_KEY_URLSCAN = "c7af4acf-276a-41f3-9559-981e6ed53304"

# Function to determine if a URL is suspicious
def is_suspicious_url(url, official_domain):
    return official_domain not in url

# Fetch domains related to a bank using the Whoxy API
def get_suspicious_domains(api_key, bank_name, official_domain):
    search_query = f"{bank_name} login"
    api_url = f"https://api.whoxy.com/?key={api_key}&whois=true&reverse=whois&search={urlencode({'q': search_query})}"

    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            response_data = response.json()
            flagged_domains = [
                entry.get("domain_name")
                for entry in response_data.get("search_result", [])
                if is_suspicious_url(entry.get("domain_name"), official_domain)
            ]
            return flagged_domains
        else:
            st.error(f"Failed to fetch data from Whoxy API: {response.status_code}")
            return []
    except requests.RequestException as e:
        st.error(f"Error while connecting to Whoxy API: {e}")
        return []

# Analyze a given URL using URLScan
def scan_url(api_key, target_url):
    headers = {"API-Key": api_key}
    payload = {"url": target_url, "visibility": "public"}

    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload)
        if response.status_code == 200:
            scan_result = response.json()
            return scan_result.get("result")
        else:
            st.error(f"URLScan analysis failed: {response.status_code}")
            return None
    except requests.RequestException as e:
        st.error(f"Error during URLScan request: {e}")
        return None

# Construct a Google Dork query for finding suspicious sites
def generate_google_dork(bank_name, official_domain):
    return f"site:{official_domain} inurl:login -{bank_name.lower()} -{official_domain}"

# Main application logic
def main():
    st.title("🔍 Scam URL Detector for Indian Banks")

    # Sidebar configuration for bank selection
    st.sidebar.header("Choose a Bank")
    selected_bank = st.sidebar.selectbox("Bank Name", BANK_LIST)
    official_domain = DOMAIN_MAP[selected_bank]

    st.write(f"### Selected Bank: {selected_bank}")
    st.write(f"**Trusted Domain:** `{official_domain}`")
    st.markdown("---")

    # URL analysis section
    st.subheader("🔎 Analyze a URL")
    user_url = st.text_input("Enter the URL to check")
    if st.button("Check URL") and user_url:
        if is_suspicious_url(user_url, official_domain):
            st.error("⚠️ This URL looks suspicious!")
        else:
            st.success("✅ The URL appears to be safe.")

    st.markdown("---")

    # Whoxy API section
    st.subheader("🌐 Discover Potentially Fraudulent Domains")
    if st.button("Search for Fake Domains"):
        domains = get_suspicious_domains(API_KEY_WHOXY, selected_bank, official_domain)
        if domains:
            st.warning("⚠️ The following suspicious domains were found:")
            for domain in domains:
                st.markdown(f"- `{domain}`")
        else:
            st.success("No suspicious domains detected.")

    st.markdown("---")

    # URLScan API section
    st.subheader("🧾 Scan URL with URLScan.io")
    url_to_scan = st.text_input("Enter a URL to analyze with URLScan")
    if st.button("Run URLScan") and url_to_scan:
        result_url = scan_url(API_KEY_URLSCAN, url_to_scan)
        if result_url:
            st.success("Scan completed successfully!")
            st.markdown(f"[🔗 View Full Analysis]({result_url})")
        else:
            st.error("Failed to complete the scan. Try again later.")

    st.markdown("---")

    # Google Dorking section
    st.subheader("🔍 Advanced Search with Google Dorking")
    if st.button("Generate Dork Query"):
        dork_query = generate_google_dork(selected_bank, official_domain)
        st.info(f"**Dork Query:** `{dork_query}`")
        st.markdown(f"[🔗 Search on Google](https://www.google.com/search?q={urlencode({'q': dork_query})})", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
