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
netsuite_account_id = os.getenv("ACCOUNT_ID")
consumer_key = os.getenv("CONSUMER_KEY")
consumer_secret = os.getenv("CONSUMER_SECRET")
token_id = os.getenv("TOKEN_ID")
token_secret = os.getenv("TOKEN_SECRET")
cribl_endpoint = os.getenv("CRIBL_ENDPOINT")
cribl_token = os.getenv("CRIBL_TOKEN")


def map_to_chronicle_fields(record: dict) -> dict:
    """
    map netsuite to chronicle field names for sending to cribl
    :param record: netsuite record
    :return: chronicle mapped record
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
        # pull the key from the mapping dict above
        key = mapping.get(k, k)
        # get does -> Return the value for key if key is in the dictionary, else default.
        # key will be value of the mapping.k or just k which may lead to unsafe behavior
        # that unsafe behavior being unexpected json key values, but the code will always
        # work

        # this builds the record by key, value pair
        chronicle_record[key] = v

    return chronicle_record


def send_single_event_to_cribl(event: dict, index: int, retries: int = 3) -> bool:
    """
    send event to cribl server
    :param event: json dict of what to send
    :param index: where in the batch the event came from
    :param retries: number of times to retry the request default is 3
    :return: boolean True is success or False if fail.
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
                return True
            else:  # TODO may want to improve error code handling for other status
                print(f"Event [{index}] failed with status: {response.status_code}")

        except Exception as e:
            print(f"Error sending event [{index}]: ", e)

        time.sleep(10)

    # failed to send update
    return False


def setup_check(args):
    missing_vars = [var for var in args if var not in os.environ]
    if missing_vars:
        raise EnvironmentError(f"Environment variable(s) {', '.join(missing_vars)} not set")


def request_setup() -> tuple:
    """
    Build the netsuite sql query to the api
    :return: headers, url, query
    """
    last_ts = (datetime.utcnow() - pd.Timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')

    # SQL filter to fetch only new records
    filter_clause = (f"WHERE LoginAudit.date > TO_TIMESTAMP('{last_ts}', "
                     f"'YYYY-MM-DD HH24:MI:SS') AND "
                     f"LoginAudit.date >= TO_DATE(SYSDATE - 1)")
#sql query
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

    url = f'https://{netsuite_account_id}.suitetalk.api.netsuite.com/services/rest/query/v1/suiteql'
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
        f'realm="{netsuite_account_id}"'
    )

    netsuite_headers = {
        'Authorization': auth_header,
        'Content-Type': 'application/json',
        'Prefer': 'transient'
    }

    return netsuite_headers, url, query


def loop(debug: bool = False) -> None:
    """
    Main batch grabbing loop for netsuite
    :param debug: if loop runs once or not
    :return: None
    """
    try:
        setup_check(args=["ACCOUNT_ID",
                          "CONSUMER_KEY",
                          "CONSUMER_SECRET",
                          "TOKEN_ID",
                          "TOKEN_SECRET",
                          "CRIBL_ENDPOINT",
                          "CRIBL_TOKEN"])
    except EnvironmentError as e:
        print(f"Environment Error: {e}")
        exit()

    while True:
        netsuite_headers, url, query = request_setup()

        try:
            # Make the SuiteQL query request
            response = requests.post(url, headers=netsuite_headers, json={"q": query})

            if response.status_code == 200:
                data = response.json().get('items', [])
                print(f"Retrieved {len(data)} records from NetSuite.")

                if data:  # if i have data
                    df = pd.DataFrame(data)
                    df.replace([float('inf'), float('-inf')], None, inplace=True)
                    df = df.where(pd.notnull(df), None)

                    # multi threading for 10 threads
                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                        futures = []
                        # build list of executions to run based on record size
                        for i, row in enumerate(df.to_dict(orient="records")):
                            mapped_event = map_to_chronicle_fields(row)

                            futures.append(executor.submit(send_single_event_to_cribl, mapped_event, i))

                        # run 10 parallel executions on bucket of records
                        concurrent.futures.wait(futures, return_when="ALL_COMPLETED")
                        # need to review this data structure
            else:
                print("Netsuite Status Code: ", response.status_code)

            # Wait before next polling iteration
            time.sleep(30)

            if debug:
                break

        except ConnectionError as e:
            print(f"Connection Error: {e}")


if __name__ == "__main__":
    loop(debug=True)
