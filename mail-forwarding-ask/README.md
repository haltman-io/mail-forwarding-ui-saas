# mail-forwarding-ask

### Create local endpoint `/ask` (whitelist)
Caddy needs an HTTP local endpoint that answer:
* **200** -> Authorized, can emit TLS for domain
* **403** -> Deny

#### Clone the `mail-forwarding` repository to create the service (node + express)

```console
sudo mkdir -p /opt/mail-forwarding-ask
git clone https://github.com/haltman-io/mail-forwarding-core.git

mv ./mail-forwarding/mail-forwarding-ask/app/ /opt/mail-forwarding-ask

cd /opt/mail-forwarding-ask
npm install
```

#### Create systemd unit

```console
sudo nano /etc/systemd/system/mail-forwarding-ask.service
```

```ini
[Unit]
Description=Haltman.io - Mail Forwarding Ask
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/mail-forwarding-ask
Environment=ALLOWLIST_PATH=/etc/mail-forwarding/allowed_domains.txt
ExecStart=/usr/bin/node /opt/mail-forwarding-ask/server.js
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Run:

```console
sudo systemctl daemon-reload
sudo systemctl enable --now mail-forwarding-ask
sudo systemctl status mail-forwarding-ask --no-pager
```

Quick test:
```console
curl -i "http://127.0.0.1:9000/ask?domain=forward.haltman.io"
curl -i "http://127.0.0.1:9000/ask?domain=unauthorized.com"
```

> Needs to return *200* for authorized domains and *403* for unauthorized domains.