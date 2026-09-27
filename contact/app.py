"""AVRG contact form: one page at /contact/ that emails the info@av-research-group.net group.

A plain WSGI app (served by gunicorn on 127.0.0.1:8003 behind nginx). GET renders
the form, POST validates it and sends one message through Amazon SES. Nothing is
stored: no database, no files, and (outside dry-run) no message content in the
logs — only the source site, the outcome and the message length.

Abuse controls, in the order a request meets them:
  - nginx rate-limits /contact/ per client IP (deploy/nginx-apex-contact.conf)
  - request body capped at MAX_BODY bytes
  - a hidden honeypot field that people never see and bots fill in
  - a signed timestamp in the form: submissions faster than MIN_SECONDS or older
    than MAX_SECONDS are rejected, and the form cannot be posted without first
    being loaded from this server
  - field length and format checks; CR/LF stripped from single-line fields
  - a per-process daily send cap (DAILY_CAP) protecting the SES quota
  - mail only ever goes to CONTACT_TO; the visitor's address is Reply-To, never
    a recipient, so the form cannot be used to relay mail to third parties
Bot-looking submissions (honeypot, too fast) get the normal "sent" page and are
dropped silently, so there is nothing to tune against.

Configuration comes from the environment (systemd EnvironmentFile on Lightsail,
see deploy/contact.env.example). CONTACT_DRY_RUN=1 logs the message instead of
sending it, for development and before an SES key exists.
"""
import datetime as dt
import hashlib
import hmac
import html
import os
import re
import sys
import time
from urllib.parse import parse_qs, urlencode

MAX_BODY = 20_000
MIN_SECONDS = 3
MAX_SECONDS = 2 * 60 * 60
DAILY_CAP = int(os.environ.get("CONTACT_DAILY_CAP", "50"))

CONTACT_TO = os.environ.get("CONTACT_TO", "info@av-research-group.net")
CONTACT_FROM = os.environ.get("CONTACT_FROM", "contact@av-research-group.net")
AWS_REGION = os.environ.get("AWS_REGION", "us-west-2")
DRY_RUN = os.environ.get("CONTACT_DRY_RUN", "").strip().lower() in ("1", "true", "yes", "on")
SECRET = os.environ.get("CONTACT_SECRET", "")

# Where a visitor came from (?from=...), shown in the email subject. Anything
# else falls back to "portal"; the value is never echoed unvalidated.
SOURCES = {
    "portal": "AVRG",
    "water": "Water Resources Monitor",
    "wiki": "AVRG Wiki",
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_sent_today = {"day": None, "count": 0}


def log(msg):
    print(f"avrg-contact: {msg}", file=sys.stderr, flush=True)


# --- form token --------------------------------------------------------------

def _sign(ts: str) -> str:
    return hmac.new(SECRET.encode(), ts.encode(), hashlib.sha256).hexdigest()


def make_token(now=None) -> str:
    ts = str(int(now if now is not None else time.time()))
    return f"{ts}.{_sign(ts)}"


def check_token(token: str, now=None):
    """Return None if the token is fresh and genuine, else a reason string."""
    now = now if now is not None else time.time()
    ts, _, sig = (token or "").partition(".")
    if not ts.isdigit() or not hmac.compare_digest(sig, _sign(ts)):
        return "bad-token"
    age = now - int(ts)
    if age < MIN_SECONDS:
        return "too-fast"
    if age > MAX_SECONDS:
        return "expired"
    return None


# --- validation --------------------------------------------------------------

def _one_line(s: str) -> str:
    return " ".join((s or "").replace("\r", " ").replace("\n", " ").split())


def validate(form: dict):
    """Return (cleaned, errors). errors maps field -> message for the visitor."""
    name = _one_line(form.get("name", ""))
    email = _one_line(form.get("email", ""))
    message = (form.get("message", "") or "").replace("\r\n", "\n").strip()
    errors = {}
    if not name:
        errors["name"] = "Please enter your name."
    elif len(name) > 100:
        errors["name"] = "Please keep your name under 100 characters."
    if not email:
        errors["email"] = "Please enter your email address so we can reply."
    elif len(email) > 254 or not EMAIL_RE.match(email):
        errors["email"] = "That doesn't look like an email address."
    if len(message) < 10:
        errors["message"] = "Please write a message (at least 10 characters)."
    elif len(message) > 5000:
        errors["message"] = "Please keep your message under 5,000 characters."
    return {"name": name, "email": email, "message": message}, errors


# --- sending -----------------------------------------------------------------

def _under_cap() -> bool:
    today = dt.date.today()
    if _sent_today["day"] != today:
        _sent_today.update(day=today, count=0)
    return _sent_today["count"] < DAILY_CAP


def send(source: str, data: dict) -> str:
    """Send (or, in dry-run, print) one message. Returns the outcome for the log:
    "dry-run", or "sent ses-id=<MessageId>" so a message can be traced in SES."""
    label = SOURCES[source]
    subject = f"[{label}] Message from {data['name']}"
    body = (f"From: {data['name']} <{data['email']}>\n"
            f"Via: {label} contact form\n"
            f"Reply to this email to answer them directly.\n"
            f"\n{data['message']}\n")
    if DRY_RUN:  # development only: shows the whole message instead of sending it
        log(f"DRY RUN — not sent. To: {CONTACT_TO} | Reply-To: {data['email']} | "
            f"Subject: {subject}\n{body}")
        _sent_today["count"] += 1
        return "dry-run"
    import boto3  # imported lazily so dry-run and tests need no AWS SDK
    resp = boto3.client("sesv2", region_name=AWS_REGION).send_email(
        FromEmailAddress=f"AVRG contact form <{CONTACT_FROM}>",
        Destination={"ToAddresses": [CONTACT_TO]},
        ReplyToAddresses=[data["email"]],
        Content={"Simple": {
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
        }},
    )
    _sent_today["count"] += 1
    return f"sent ses-id={resp.get('MessageId', '?')}"


# --- pages -------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact · Antelope Valley Research Group</title>
    <meta name="robots" content="noindex">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <style>
        body {{ background: radial-gradient(1200px 600px at 50% -10%, #16324a 0%, #212529 45%) no-repeat, #212529; }}
        .hero-icon {{ color: #4dabf7; }}
        .hp {{ position: absolute; left: -10000px; width: 1px; height: 1px; overflow: hidden; }}
        footer {{ font-size: .85rem; }}
    </style>
</head>
<body>
<main class="container py-5" style="max-width: 720px;">
    <header class="text-center mb-4">
        <div class="display-6 mb-2"><i class="bi bi-envelope hero-icon"></i></div>
        <h1 class="fw-bold h2">Contact us</h1>
        <p class="text-secondary mb-0">{lead}</p>
    </header>
    {content}
    <footer class="text-secondary text-center mt-5 pt-4 border-top border-secondary">
        <a class="text-info text-decoration-none" href="https://av-research-group.net/">Antelope Valley Research Group</a>
        {back}
    </footer>
</main>
</body>
</html>
"""

BACK_LINKS = {
    "water": ' · <a class="text-info text-decoration-none" '
             'href="https://water.av-research-group.net/">Back to the Water Resources Monitor</a>',
    "wiki": ' · <a class="text-info text-decoration-none" '
            'href="https://wiki.av-research-group.net/">Back to the wiki</a>',
    "portal": "",
}


def _field_error(errors, field):
    if field not in errors:
        return "", ""
    return " is-invalid", f'<div class="invalid-feedback">{html.escape(errors[field])}</div>'


def render_form(source, values=None, errors=None, notice=""):
    values, errors = values or {}, errors or {}
    e = html.escape
    parts = {f: _field_error(errors, f) for f in ("name", "email", "message")}
    content = f"""
    {notice}
    <form method="post" action="/contact/" class="card bg-dark border-secondary" novalidate>
      <div class="card-body">
        <input type="hidden" name="token" value="{e(make_token())}">
        <input type="hidden" name="from" value="{e(source)}">
        <div class="hp" aria-hidden="true">
          <label for="website">Leave this field empty</label>
          <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
        </div>
        <div class="mb-3">
          <label class="form-label" for="name">Your name</label>
          <input class="form-control{parts['name'][0]}" id="name" name="name" maxlength="100"
                 autocomplete="name" required value="{e(values.get('name', ''))}">
          {parts['name'][1]}
        </div>
        <div class="mb-3">
          <label class="form-label" for="email">Your email</label>
          <input class="form-control{parts['email'][0]}" id="email" name="email" type="email"
                 maxlength="254" autocomplete="email" required value="{e(values.get('email', ''))}">
          {parts['email'][1]}
          <div class="form-text">Only used to reply to you. Nothing you send is stored on this site.</div>
        </div>
        <div class="mb-3">
          <label class="form-label" for="message">Message</label>
          <textarea class="form-control{parts['message'][0]}" id="message" name="message" rows="7"
                    maxlength="5000" required>{e(values.get('message', ''))}</textarea>
          {parts['message'][1]}
        </div>
        <button class="btn btn-info" type="submit"><i class="bi bi-send me-1"></i>Send</button>
      </div>
    </form>"""
    return PAGE.format(lead="Questions, corrections, or ideas — we read everything.",
                       content=content, back=BACK_LINKS[source])


def render_sent(source):
    content = """
    <div class="card bg-dark border-secondary"><div class="card-body text-center py-4">
      <h2 class="h5"><i class="bi bi-check-circle text-success me-2"></i>Thank you — your message was sent.</h2>
      <p class="text-secondary mb-0">We'll reply to the email address you gave.</p>
    </div></div>"""
    return PAGE.format(lead="", content=content, back=BACK_LINKS[source])


def notice(kind, text):
    return f'<div class="alert alert-{kind}">{html.escape(text)}</div>'


# --- WSGI --------------------------------------------------------------------

HEADERS = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "same-origin"),
    ("Content-Security-Policy",
     "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
     "font-src https://cdn.jsdelivr.net; img-src 'self' data:; "
     "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
]


def _respond(start_response, status, body="", extra=()):
    data = body.encode()
    start_response(status, HEADERS + [("Content-Length", str(len(data)))] + list(extra))
    return [data]


def _source(value):
    value = (value or "").strip().lower()
    return value if value in SOURCES else "portal"


def application(environ, start_response):
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "GET")
    query = parse_qs(environ.get("QUERY_STRING", ""))
    if path not in ("/contact", "/contact/"):
        return _respond(start_response, "404 Not Found", "Not found")
    if path == "/contact":
        return _respond(start_response, "301 Moved Permanently", "",
                        [("Location", "/contact/" + (f"?{environ['QUERY_STRING']}"
                                                     if environ.get("QUERY_STRING") else ""))])

    if method in ("GET", "HEAD"):
        source = _source(query.get("from", [""])[0])
        page = render_sent(source) if query.get("sent") == ["1"] else render_form(source)
        return _respond(start_response, "200 OK", "" if method == "HEAD" else page)

    if method != "POST":
        return _respond(start_response, "405 Method Not Allowed", "Method not allowed",
                        [("Allow", "GET, HEAD, POST")])

    if not SECRET:
        log("CONTACT_SECRET is not set; refusing to accept submissions")
        return _respond(start_response, "503 Service Unavailable", render_form(
            "portal", notice=notice("danger", "The contact form is temporarily unavailable.")))
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length <= 0 or length > MAX_BODY:
        return _respond(start_response, "413 Payload Too Large", "Request too large")
    form = {k: v[0] for k, v in parse_qs(
        environ["wsgi.input"].read(length).decode("utf-8", "replace")).items()}
    source = _source(form.get("from"))
    sent_url = "/contact/?" + urlencode({"sent": "1", "from": source})

    reason = "honeypot" if form.get("website") else check_token(form.get("token", ""))
    if reason in ("honeypot", "too-fast"):
        log(f"dropped ({reason}) from={source}")
        return _respond(start_response, "303 See Other", "", [("Location", sent_url)])
    if reason:  # bad or expired token: a real person with a stale page gets a fresh form
        log(f"rejected ({reason}) from={source}")
        return _respond(start_response, "400 Bad Request", render_form(
            source, values=form, notice=notice(
                "warning", "This form had expired. Please check your message and send it again.")))

    data, errors = validate(form)
    if errors:
        return _respond(start_response, "400 Bad Request",
                        render_form(source, values=form, errors=errors))
    if not _under_cap():
        log(f"daily cap {DAILY_CAP} reached; not sending from={source}")
        return _respond(start_response, "503 Service Unavailable", render_form(
            source, values=form, notice=notice(
                "danger", "The contact form is busy right now. Please try again tomorrow.")))
    try:
        outcome = send(source, data)
    except Exception as e:  # SES/network failure: keep the visitor's text, say so plainly
        log(f"send failed from={source}: {type(e).__name__}: {e}")
        return _respond(start_response, "502 Bad Gateway", render_form(
            source, values=form, notice=notice(
                "danger", "Sorry — your message could not be sent. Please try again in a few minutes.")))
    log(f"{outcome} from={source} ({len(data['message'])} chars)")
    return _respond(start_response, "303 See Other", "", [("Location", sent_url)])
