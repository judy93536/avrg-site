"""Tests for the contact form. Standard library only; no AWS calls.

    cd contact && python3 -m unittest -v
"""
import io
import os
import unittest
from unittest import mock
from urllib.parse import urlencode

os.environ.update(CONTACT_SECRET="test-secret", CONTACT_DRY_RUN="1", CONTACT_DAILY_CAP="3")
import app  # noqa: E402


def call(method="GET", path="/contact/", query="", form=None, raw=None):
    body = raw if raw is not None else (urlencode(form).encode() if form is not None else b"")
    env = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
           "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
    out = {}

    def start_response(status, headers):
        out["status"], out["headers"] = status, dict(headers)
    out["body"] = b"".join(app.application(env, start_response)).decode()
    return out


def good(**over):
    f = {"token": app.make_token(now=1000), "from": "water", "website": "",
         "name": "Ada Lovelace", "email": "ada@example.org",
         "message": "How is percent of normal computed for SWE?"}
    f.update(over)
    return f


class ContactTests(unittest.TestCase):
    def setUp(self):
        app._sent_today.update(day=None, count=0)
        self.clock = mock.patch.object(app.time, "time", return_value=1000 + 30)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.send = mock.patch.object(app, "send", wraps=app.send)
        self.sent = self.send.start()
        self.addCleanup(self.send.stop)

    def test_get_renders_form_with_token_and_source(self):
        r = call(query="from=water")
        self.assertEqual(r["status"], "200 OK")
        self.assertIn('name="token"', r["body"])
        self.assertIn('value="water"', r["body"])
        self.assertIn("Back to the Water Resources Monitor", r["body"])
        self.assertEqual(r["headers"]["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", r["headers"]["Content-Security-Policy"])

    def test_unknown_source_falls_back_to_portal(self):
        r = call(query="from=<script>")
        self.assertIn('value="portal"', r["body"])
        self.assertNotIn("<script>", r["body"])

    def test_valid_post_sends_once_and_redirects(self):
        r = call("POST", form=good())
        self.assertEqual(r["status"], "303 See Other")
        self.assertEqual(r["headers"]["Location"], "/contact/?sent=1&from=water")
        self.sent.assert_called_once()
        source, data = self.sent.call_args.args
        self.assertEqual(source, "water")
        self.assertEqual(data["email"], "ada@example.org")

    def test_log_says_dry_run_and_real_sends_carry_ses_id(self):
        with mock.patch.object(app, "log") as log:
            call("POST", form=good())
        self.assertTrue(log.call_args_list[-1].args[0].startswith("dry-run from=water"))
        fake = mock.MagicMock()
        fake.client.return_value.send_email.return_value = {"MessageId": "0100abc"}
        with mock.patch.object(app, "DRY_RUN", False), \
             mock.patch.dict("sys.modules", {"boto3": fake}), \
             mock.patch.object(app, "log") as log:
            call("POST", form=good())
        self.assertTrue(log.call_args_list[-1].args[0].startswith("sent ses-id=0100abc from=water"))

    def test_default_recipient_is_the_group(self):
        self.assertEqual(app.CONTACT_TO, "info@av-research-group.net")

    def test_sent_page(self):
        r = call(query="sent=1&from=water")
        self.assertIn("your message was sent", r["body"])

    def test_honeypot_is_dropped_silently(self):
        r = call("POST", form=good(website="http://spam.example"))
        self.assertEqual(r["status"], "303 See Other")
        self.sent.assert_not_called()

    def test_too_fast_is_dropped_silently(self):
        r = call("POST", form=good(token=app.make_token(now=1000 + 29)))
        self.assertEqual(r["status"], "303 See Other")
        self.sent.assert_not_called()

    def test_forged_and_expired_tokens_are_rejected(self):
        for tok in ("1000.deadbeef", "garbage", "", app.make_token(now=1000 + 30 - 3 * 60 * 60)):
            r = call("POST", form=good(token=tok))
            self.assertEqual(r["status"], "400 Bad Request", tok)
        self.sent.assert_not_called()

    def test_validation_errors_keep_text_and_escape_it(self):
        r = call("POST", form=good(email="not-an-email", message="<b>hi</b> there, x"))
        self.assertEqual(r["status"], "400 Bad Request")
        self.assertIn("doesn&#x27;t look like an email", r["body"])
        self.assertIn("&lt;b&gt;hi&lt;/b&gt;", r["body"])
        self.assertNotIn("<b>hi</b>", r["body"])
        self.sent.assert_not_called()

    def test_header_injection_is_flattened(self):
        call("POST", form=good(name="Eve\r\nBcc: victim@example.org"))
        data = self.sent.call_args.args[1]
        self.assertNotIn("\n", data["name"])
        self.assertNotIn("\r", data["name"])

    def test_reply_to_is_visitor_and_recipient_is_fixed(self):
        with mock.patch.object(app, "DRY_RUN", False), \
             mock.patch.dict("sys.modules", {"boto3": mock.MagicMock()}) as mods:
            call("POST", form=good(email="someone@example.org"))
            kwargs = mods["boto3"].client.return_value.send_email.call_args.kwargs
        self.assertEqual(kwargs["Destination"], {"ToAddresses": [app.CONTACT_TO]})
        self.assertEqual(kwargs["ReplyToAddresses"], ["someone@example.org"])
        self.assertIn(app.CONTACT_FROM, kwargs["FromEmailAddress"])
        self.assertTrue(kwargs["Content"]["Simple"]["Subject"]["Data"].startswith(
            "[Water Resources Monitor]"))

    def test_daily_cap(self):
        for _ in range(3):
            self.assertEqual(call("POST", form=good())["status"], "303 See Other")
        r = call("POST", form=good())
        self.assertEqual(r["status"], "503 Service Unavailable")
        self.assertEqual(self.sent.call_count, 3)

    def test_send_failure_keeps_message(self):
        with mock.patch.object(app, "send", side_effect=RuntimeError("SES down")):
            r = call("POST", form=good())
        self.assertEqual(r["status"], "502 Bad Gateway")
        self.assertIn("How is percent of normal", r["body"])

    def test_oversize_and_empty_bodies(self):
        self.assertEqual(call("POST", raw=b"x" * (app.MAX_BODY + 1))["status"], "413 Payload Too Large")
        self.assertEqual(call("POST", raw=b"")["status"], "413 Payload Too Large")

    def test_other_paths_and_methods(self):
        self.assertEqual(call(path="/other")["status"], "404 Not Found")
        self.assertEqual(call(path="/contact", query="from=wiki")["headers"]["Location"],
                         "/contact/?from=wiki")
        self.assertEqual(call("PUT")["status"], "405 Method Not Allowed")

    def test_missing_secret_refuses(self):
        with mock.patch.object(app, "SECRET", ""):
            r = call("POST", form=good())
        self.assertEqual(r["status"], "503 Service Unavailable")
        self.sent.assert_not_called()


if __name__ == "__main__":
    unittest.main()
