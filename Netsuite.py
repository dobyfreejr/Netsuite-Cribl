import os
import time
import uuid
import hmac
import hashlib
import base64
import json
import pandas as pd
import requests
import concurrent.futures
from urllib.parse import quote
from dotenv import load_dotenv
import urllib3
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

# Optional: disable TLS warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load configuration from environment
account_id = os.getenv("ACCOUNT_ID")
consumer_key = os.getenv("CONSUMER_KEY")
consumer_secret = os.getenv("CONSUMER_SECRET")
token_id = os.getenv("TOKEN_ID")
token_secret = os.getenv("TOKEN_SECRET")
cribl_endpoint = os.getenv("CRIBL_ENDPOINT")
cribl_token = os.getenv("CRIBL_TOKEN")

# Path to the file that stores the last processed timestamp
STATE_FILE = "last_timestamp.txt"

def load_last_timestamp():
    """Load the last timestamp from file. If not found, default to 24 hours ago."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return f.read().strip()
    return (datetime.utcnow() - pd.Timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')

def save_last_timestamp(ts):
    """Save the latest timestamp to file."""
    with open(STATE_FILE, "w") as f:
        f.write(ts)

def map_to_chronicle_fields(record):
    """
    Map NetSuite field names to Chronicle-compatible field names.
    Unmapped fields are retained as-is.
    """
    mapping = {
        "date": "Login_Audit_Trail_Date",
        "detail": "Login_Audit_Trail_Detail",
        "emailAddress": "Login_Audit_Trail_Email_Address",
        "ipAddress": "Login_Audit_Trail_IP_Address",
        "requestUri": "Login_Audit_Trail_Request_URI",
        "role": "Login_Audit_Trail_Role",
        "secChallenge": "Login_Audit_Trail_Security_Challenge",
        "status": "Login_Audit_Trail_Status",
        "oAuthAccessTokenName": "Login_Audit_Trail_Access_Token_Name",
        "oAuthAppName": "Login_Audit_Trail_Application",
        "user": "Login_Audit_Trail_User",
        "userAgent": "Login_Audit_Trail_User_Agent"
    }

    chronicle_record = {}
    for k, v in record.items():
        key = mapping.get(k, k)
        try:
            json.dumps(v)  # Validate serializability
        except (TypeError, OverflowError):
            v = str(v)
        chronicle_record[key] = v
    return chronicle_record

def send_single_event_to_cribl(event, index, retries=3):
    """
    Send a single event to Cribl endpoint with retry logic.
    """
    headers = {
        'Content-Type': 'application/json',
        'Connection': 'close'
    }
    if cribl_token:
        headers['Authorization'] = f'Bearer {cribl_token}'

    payload = {
        "msg1": json.dumps(event),
        "metadata": {
            "log_type": "ORACLE_NETSUITE",
            "event_type": "USER_UNCATEGORIZED"
        }
    }

    for attempt in range(retries):
        try:
            response = requests.post(
                cribl_endpoint,
                headers=headers,
                data=json.dumps(payload),
                timeout=10,
                verify=True
            )
            if response.status_code == 200:
                print(f"Event [{index}] sent. Cribl status: {response.status_code}")
                return
            else:
                print(f"Event [{index}] failed with status: {response.status_code}")
        except Exception as e:
            print(f"Event [{index}] attempt {attempt + 1} failed: {e}")
        time.sleep(2 ** attempt)

# Main polling loop
while True:
    last_ts = load_last_timestamp()

    # SQL filter to fetch only new records
    filter_clause = f"WHERE LoginAudit.date > TO_TIMESTAMP('{last_ts}', 'YYYY-MM-DD HH24:MI:SS') AND LoginAudit.date >= TO_DATE(SYSDATE - 1)"

    # SuiteQL query to fetch audit logs
    query = f"""
    SELECT LoginAudit.date,
           LoginAudit.detail,
           LoginAudit.emailAddress,
           LoginAudit.ipAddress,
           LoginAudit.requestUri,
           LoginAudit.role,
           LoginAudit.secChallenge,
           LoginAudit.status,
           LoginAudit.oAuthAccessTokenName,
           LoginAudit.oAuthAppName,
           LoginAudit.user,
           LoginAudit.userAgent
    FROM LoginAudit
    {filter_clause}
    ORDER BY LoginAudit.date ASC
    """

    url = f'https://{account_id}.suitetalk.api.netsuite.com/services/rest/query/v1/suiteql'
    nonce = uuid.uuid4().hex
    timestamp = str(int(time.time()))
    signature_method = 'HMAC-SHA256'
    version = '1.0'

    # Build OAuth base string and signature
    base_string = f"POST&{quote(url, safe='')}&" + quote(
        f"oauth_consumer_key={consumer_key}&"
        f"oauth_nonce={nonce}&"
        f"oauth_signature_method={signature_method}&"
        f"oauth_timestamp={timestamp}&"
        f"oauth_token={token_id}&"
        f"oauth_version={version}", safe=''
    )

    key = f"{quote(consumer_secret)}&{quote(token_secret)}"
    signature = base64.b64encode(
        hmac.new(key.encode(), base_string.encode(), hashlib.sha256).digest()
    ).decode()

    # OAuth Authorization header
    auth_header = (
        f'OAuth '
        f'oauth_consumer_key="{consumer_key}", '
        f'oauth_token="{token_id}", '
        f'oauth_signature_method="{signature_method}", '
        f'oauth_timestamp="{timestamp}", '
        f'oauth_nonce="{nonce}", '
        f'oauth_version="{version}", '
        f'oauth_signature="{quote(signature)}", '
        f'realm="{account_id}"'
    )

    netsuite_headers = {
        'Authorization': auth_header,
        'Content-Type': 'application/json',
        'Prefer': 'transient'
    }

    # Make the SuiteQL query request
    response = requests.post(url, headers=netsuite_headers, json={"q": query})

    if response.status_code == 200:
        data = response.json().get('items', [])
        print(f"Retrieved {len(data)} records from NetSuite.")

        if data:
            df = pd.DataFrame(data)
            df.replace([float('inf'), float('-inf')], None, inplace=True)
            df = df.where(pd.notnull(df), None)

            if cribl_endpoint:
                print("Sending each event to Cribl individually...")
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = []
                    for i, row in enumerate(df.to_dict(orient="records")):
                        mapped_event = map_to_chronicle_fields(row)
                        futures.append(executor.submit(send_single_event_to_cribl, mapped_event, i))
                    concurrent.futures.wait(futures)

                # Save latest processed timestamp
                latest_ts = df['date'].max()
                if latest_ts:
                    ts_str = pd.to_datetime(latest_ts).strftime('%Y-%m-%d %H:%M:%S')
                    save_last_timestamp(ts_str)
            else:
                print("Cribl endpoint not configured.")
        else:
            print("No new records found.")
    else:
        print("NetSuite API error:", response.status_code)
        print(response.text)

    # Wait before next polling iteration
    time.sleep(30)
