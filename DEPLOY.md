# Deploying on Proxmox

The reviewer is a small FastAPI service. GitHub sends it webhooks, so it needs a
**public HTTPS URL**. The simplest reliable setup on Proxmox:

```
Internet ──HTTPS──> Caddy (TLS) ──HTTP──> prsec container :8000
                    (reverse proxy)       (Docker)
```

## 1. Create a container on Proxmox

Create a **Debian 12** LXC (or a small VM) — 1 vCPU, 1–2 GB RAM, 8 GB disk is plenty.
If you use an LXC, make it a **privileged** container or enable nesting so Docker runs:
in the container's Options, set **Features → nesting = 1**.

## 2. Install Docker in the container

```bash
apt update && apt install -y docker.io docker-compose-plugin git
systemctl enable --now docker
```

## 3. Get the code and configure secrets

```bash
git clone https://github.com/lansiquo/PR_Reviewer.git
cd PR_Reviewer
cp .env.example .env
```

Edit `.env`:
- `GITHUB_APP_ID` — from your GitHub App's settings page.
- `GITHUB_WEBHOOK_SECRET` — a long random string (`openssl rand -hex 32`); set the
  same value in the App's webhook config.
- Keep `ALLOW_UNVERIFIED_WEBHOOKS=0` so forged webhooks are rejected.

Put your App's private key where the container expects it:

```bash
mkdir -p secrets
# paste the .pem you downloaded from the GitHub App:
nano secrets/github-app.pem
chmod 600 secrets/github-app.pem
```

## 4. Build and run

```bash
docker compose up -d --build
curl -s http://127.0.0.1:8000/health      # -> {"ok": true, ...}
```

The service listens on `127.0.0.1:8000` only; the reverse proxy exposes it publicly.

## 5. TLS reverse proxy (Caddy — gets a free cert automatically)

```bash
apt install -y caddy
```

`/etc/caddy/Caddyfile`:

```
prsec.yourdomain.com {
    reverse_proxy 127.0.0.1:8000
}
```

```bash
systemctl restart caddy
```

Point `prsec.yourdomain.com` (DNS A record) at your public IP, and forward 80/443
to this container. Caddy fetches and renews the certificate on its own.

## 6. Configure the GitHub App

In the App's settings:
- **Webhook URL:** `https://prsec.yourdomain.com/webhook`
- **Webhook secret:** the same `GITHUB_WEBHOOK_SECRET`.
- **Permissions:** Pull requests (Read), Checks (Read & write), Contents (Read),
  Commit statuses (Read & write).
- **Subscribe to events:** Pull request.

Install the App on a repo, open a PR, and a `RobinSec` check appears.

## Updating

```bash
git pull && docker compose up -d --build
```

## Logs

```bash
docker compose logs -f prsec
```

## Alternative: systemd (no Docker)

If you would rather not use Docker:

```bash
apt install -y python3-venv git
git clone https://github.com/lansiquo/PR_Reviewer.git && cd PR_Reviewer
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

`/etc/systemd/system/prsec.service`:

```ini
[Unit]
Description=PR Security Reviewer
After=network.target

[Service]
WorkingDirectory=/root/PR_Reviewer
EnvironmentFile=/root/PR_Reviewer/.env
ExecStart=/root/PR_Reviewer/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now prsec
```

Still put Caddy in front for HTTPS (step 5).
