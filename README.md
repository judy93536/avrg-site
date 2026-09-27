# avrg-site — Antelope Valley Research Group portal and contact form

Serves `https://av-research-group.net` from the Lightsail instance (35.167.33.45),
alongside the water site (`water.*`) and Wiki.js (`wiki.*`), which live elsewhere.

```
portal/index.html   the static landing page (nginx root /var/www/av-research-group)
contact/app.py      the /contact/ form: a small WSGI app that emails
                    judy@av-research-group.net through Amazon SES
contact/test_app.py tests (standard library only; no AWS calls)
deploy/             systemd unit, nginx snippets, .env template
```

## Contact form

- `GET /contact/?from=water|wiki|portal` renders the form; `from` only selects
  the label in the email subject and the "back" link.
- `POST /contact/` validates and sends one email: From
  `contact@av-research-group.net`, To `judy@av-research-group.net`, Reply-To the
  visitor. Nothing is stored. See the docstring in `contact/app.py` for the
  abuse controls (nginx rate limit, honeypot, signed timestamp, length checks,
  daily cap, fixed recipient).
- SES: domain identity `av-research-group.net` in **us-west-2**, verified by
  Easy DKIM. DNS lives in the **Lightsail DNS zone**, not Route53 (the Route53
  zone for this domain is not delegated). Sending uses the send-only IAM user
  `avrg-contact-sender`.

### Develop and test on z8

```bash
cd contact && python3 -m unittest -v
# run it (dry run: messages are printed, not sent)
CONTACT_SECRET=dev CONTACT_DRY_RUN=1 python3 -c \
  "from wsgiref.simple_server import make_server; import app; make_server('127.0.0.1', 8020, app.application).serve_forever()"
# then open http://localhost:8020/contact/?from=water
```

### Deploy on Lightsail (first time)

1. Clone to `~/avrg-site` (read-only deploy key), `python3 -m venv .venv`,
   `.venv/bin/pip install -r contact/requirements.txt`.
2. `cp deploy/contact.env.example contact/.env && chmod 600 contact/.env`; set
   `CONTACT_SECRET` (random) and keep `CONTACT_DRY_RUN=1` until the SES key is in.
3. `sudo cp deploy/avrg-contact.service /etc/systemd/system/` then
   `sudo systemctl daemon-reload && sudo systemctl enable --now avrg-contact`.
4. `sudo cp deploy/nginx-contact-ratelimit.conf /etc/nginx/conf.d/avrg-contact-ratelimit.conf`;
   add `deploy/nginx-apex-contact.location` to the apex server block;
   `sudo nginx -t && sudo systemctl reload nginx`.
5. Portal: `sudo cp portal/index.html /var/www/av-research-group/index.html`.
6. Put the SES key in `contact/.env`, set `CONTACT_DRY_RUN=0`, restart, send a
   test message.
