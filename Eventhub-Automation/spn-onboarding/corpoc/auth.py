"""HTTP and Microsoft identity platform helpers (no MSAL, standard library only)."""

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com"

# Microsoft Graph Command Line Tools: the public client Connect-MgGraph uses.
# The setup scripts sign the cor. operator in with it (as the PS script did).
GRAPH_CLI_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"


class HttpError(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {error_text(body)}")


def error_text(body):
    """The readable part of a Graph or token-endpoint error body."""
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            return f"{err.get('code')}: {err.get('message')}"
        if err:
            desc = (body.get("error_description") or "").split("\r\n")[0]
            return f"{err}: {desc}".strip(": ")
    return str(body)[:300]


def http(method, url, token=None, json_body=None, form=None, timeout=30, raw=None, content_type=None):
    """(status, parsed body). Network errors raise; HTTP errors are returned.
    raw + content_type send bytes as they are (e.g. an image)."""
    data = None
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if raw is not None:
        data = raw
        headers["Content-Type"] = content_type or "application/octet-stream"
    elif json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    try:
        body = json.loads(raw) if raw else None
    except ValueError:
        body = raw.decode("utf-8", "replace")
    return status, body


def graph(method, path, token, body=None):
    """Graph call that raises HttpError on failure. path: '/applications' or a full URL."""
    url = path if path.startswith("https://") else f"{GRAPH}/v1.0{path}"
    status, resp = http(method, url, token=token, json_body=body)
    if status >= 400:
        raise HttpError(status, resp)
    return resp


def _token(tenant, form):
    status, body = http("POST", f"{LOGIN}/{tenant}/oauth2/v2.0/token", form=form)
    if status != 200:
        raise HttpError(status, body)
    return body


def client_credentials(tenant, client_id, secret, audience):
    return _token(tenant, {"grant_type": "client_credentials", "client_id": client_id,
                           "client_secret": secret, "scope": f"{audience}/.default"})["access_token"]


def claims(token):
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def pkce():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize_url(tenant, client_id, redirect_uri, scopes, state, challenge, prompt="select_account"):
    query = {"client_id": client_id, "response_type": "code", "response_mode": "query",
             "redirect_uri": redirect_uri, "scope": " ".join(scopes), "state": state,
             "code_challenge": challenge, "code_challenge_method": "S256"}
    if prompt:
        query["prompt"] = prompt
    return f"{LOGIN}/{tenant}/oauth2/v2.0/authorize?{urllib.parse.urlencode(query)}"


def redeem_code(tenant, client_id, code, redirect_uri, verifier, scopes):
    return _token(tenant, {"grant_type": "authorization_code", "client_id": client_id, "code": code,
                           "redirect_uri": redirect_uri, "code_verifier": verifier,
                           "scope": " ".join(scopes)})


def interactive_login(scopes, tenant="organizations", client_id=GRAPH_CLI_CLIENT_ID, port=8765):
    """Browser sign-in with a one-shot loopback listener (auth code + PKCE)."""
    verifier, challenge = pkce()
    state = secrets.token_urlsafe(16)
    redirect = f"http://localhost:{port}"
    result = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            query = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
            if "code" not in query and "error" not in query:
                self.send_response(404)
                self.end_headers()
                return
            result.update(query)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<p style='font-family:sans-serif'>Signed in. Close this tab and return to the terminal.</p>")

        def log_message(self, *args):
            pass

    server = HTTPServer(("localhost", port), Handler)
    server.timeout = 1
    url = authorize_url(tenant, client_id, redirect, scopes, state, challenge)
    print(f"Opening the browser to sign in. If it does not open, browse to:\n{url}\n")
    webbrowser.open(url)
    deadline = time.time() + 300
    while not result and time.time() < deadline:
        server.handle_request()
    server.server_close()
    if not result:
        raise SystemExit("Sign-in timed out.")
    if "error" in result:
        raise SystemExit(f"Sign-in failed: {result['error']}: {result.get('error_description', '')}")
    if result.get("state") != state:
        raise SystemExit("Sign-in failed: state mismatch.")
    return redeem_code(tenant, client_id, result["code"], redirect, verifier, scopes)["access_token"]


def device_code_login(scopes, tenant="organizations", client_id=GRAPH_CLI_CLIENT_ID):
    status, body = http("POST", f"{LOGIN}/{tenant}/oauth2/v2.0/devicecode",
                        form={"client_id": client_id, "scope": " ".join(scopes)})
    if status != 200:
        raise HttpError(status, body)
    print(body["message"])
    interval = int(body.get("interval", 5))
    deadline = time.time() + int(body.get("expires_in", 900))
    while time.time() < deadline:
        time.sleep(interval)
        status, tok = http("POST", f"{LOGIN}/{tenant}/oauth2/v2.0/token",
                           form={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                 "client_id": client_id, "device_code": body["device_code"]})
        if status == 200:
            return tok["access_token"]
        err = tok.get("error") if isinstance(tok, dict) else None
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        raise HttpError(status, tok)
    raise SystemExit("The device code expired.")
