# tools.py - ENTIRE integration in 15 lines

import requests, os

HOST = os.getenv('OPENSEARCH_HOST', 'localhost')
PORT = os.getenv('OPENSEARCH_PORT', '443')
AUTH = (os.getenv('OPENSEARCH_USER'), os.getenv('OPENSEARCH_PASSWORD'))

def execute_opensearch(path, method="GET", body=None):
    """Execute ANY OpenSearch query. AI decides what to run."""
    url = f"https://{HOST}:{PORT}/api/console/proxy"
    params = {"path": path, "method": method}
    headers = {'Content-Type': 'application/json', 'osd-xsrf': 'true'}

    return requests.get(url, params=params, auth=AUTH, headers=headers, verify=False).json() if method == "GET" else requests.post(url, params=params, json=body, auth=AUTH, headers=headers, verify=False).json()
