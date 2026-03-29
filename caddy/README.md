# Caddy Server

Simple setup guide.

## Setup

### Static files structure (e.g: html css)

```console
sudo mkdir -p /var/www/mail-forwarding
sudo rsync -av ./dist/ /var/www/mail-forwarding/
```

### Instal Caddy on Debian/Ubuntu

Reference: https://caddyserver.com/docs/install

```console
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
chmod o+r /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

### Caddy apply & reload

```console
sudo caddy fmt --overwrite /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo systemctl status caddy --no-pager
```