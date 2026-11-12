# Bunny Tale

> **Disclaimer:** Due to ongoing health issues I am no longer able to concentrate on developing software by myself. This project is therefore **vibe-coded**: written together with an AI assistant (Claude) and directed, tested and run by me. It is not a demo or proof of concept. It exists because I need it: it fixes a real problem in my day-to-day life and is in daily use. Read the code and the security notes below with that in mind.

A small, self-hosted group chat in a single room, built as a PWA, with messages encrypted at rest. It runs on top of an existing **Bunny** file server (cutebunny.io): users sign in with their Bunny account, encryption keys and attachments live on that server, and this app only keeps encrypted rows in SQLite.

It is the sibling of *Bunny Interactive* (the file-manager web client) and shares its login conventions, dark theme and hardware-ID scheme. It does not modify or depend on Interactive's code.

## Features

- Single shared room, live updates over Server-Sent Events
- Text with basic markdown (bold, italic, strike, inline/fenced code, quotes, lists, links)
- Photos, videos, audio and files, voice messages (record, listen, send), share-to-app from the system share sheet
- GIF picker with GIPHY and/or Klipy (optional, per-user choice)
- Replies (also by swiping), hearts, delete own messages, nicknames, link previews and tap-to-load embeds
- Opt-in web push notifications (own VAPID / RFC 8291 implementation, no third-party SDK)
- "Wipe chat" for any user, automatic wipe after inactivity
- Optional fake "502 Bad Gateway" screen, opened by tapping its icon three times
- Installable PWA (manifest, service worker, offline page)

## How it works

```
 Browser (PWA) ──HTTPS──▶ Bunny Tale (Flask + gunicorn) ──HTTPS──▶ Bunny server
                              │                                      ├─ .bunnyc  (key seed)
                              └─ SQLite (/data)                      └─ .bunnyc.bc-*.ext (attachments)
                                 encrypted message rows
```

**Login.** The user enters license key, email and password. The app logs in against the Bunny API with the same headers and hardware ID as Bunny Interactive (`HWID_SALT` must be identical to Interactive's). One Bunny session per account is shared by all of that account's devices, refreshed and re-established automatically. "Stay signed in" keeps the credentials Fernet-encrypted in `/data/remember.json`, with the key from `REMEMBER_KEY` or a generated `/data/remember.key`.

**Keys and encryption.**
- A random seed is stored once as `.bunnyc` on the Bunny server. A *blanket key* is derived from it with HKDF.
- Every message gets its own random 256-bit AES-GCM key. The message body is encrypted with that key; the per-message key is sealed with the blanket key and stored in the same row.
- Without the Bunny account (and so without `.bunnyc`), the SQLite file is unreadable.

**Attachments.** Uploads are streamed straight through to the Bunny server under a random name with the prefix `.bunnyc.` (so file clients can hide them). Only the reference is stored in SQLite, and files are served only if they belong to a message.

**GIFs.** Calls go from each user's browser directly to GIPHY or Klipy (as their terms require). Messages store only an id (GIPHY) or a slug plus two image URLs on `static.klipy.com` (Klipy), and every viewer's browser loads the picture itself. The server validates these references strictly.

**Wipe.** Deletes all rows and attachments, removes `.bunnyc`, runs `VACUUM` (SQLite runs with `secure_delete`), and locks writing for 5 seconds. A janitor thread does the same after `AUTOWIPE_HOURS` without activity.

**Concurrency.** One gunicorn worker with 128 threads: sessions and live subscribers are held in memory, and each open chat holds one thread for its SSE stream. Do not raise the worker count.

## Deployment

```bash
git clone https://github.com/lyvielle/bunny-tale
cd bunny-tale
# edit docker-compose.yml: set HWID_SALT and SECRET_KEY
docker compose up -d --build
```

The app listens on port 8000 inside the container. Compose publishes it as `${BIND_ADDR}:${HOST_PORT}`; both are read by Compose itself (from the shell or a `.env` file next to `docker-compose.yml`), not passed into the container:

| Variable | Default | Purpose |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0` | Host address to bind. Use `127.0.0.1` when a reverse proxy on the same host is the only client |
| `HOST_PORT` | `8001` | Host port to publish |

Example `.env`: `BIND_ADDR=127.0.0.1` and `HOST_PORT=8001`.

Put it behind a reverse proxy with HTTPS: service worker, microphone access, push and "install app" all require a secure context. For SSE, disable proxy buffering and allow long-lived responses.

### Application configuration (container environment)

| Variable | Default | Purpose |
|---|---|---|
| `BUNNY_API` | `https://cutebunny.io` | Bunny server base URL |
| `HWID_SALT` | `change-me` | Hardware-ID salt; **must equal Bunny Interactive's** |
| `SECRET_KEY` | random per start | Flask session signing key; set it, or everyone is logged out on restart |
| `AUTOWIPE_HOURS` | `48` | Wipe after this long without activity (`0` = off) |
| `GIPHY_API_KEY` | – | Enables GIPHY in the GIF picker |
| `KLIPY_API_KEY` | – | Enables Klipy; set either, both or none |
| `GIPHY_RATING` | `pg-13` | `g`, `pg`, `pg-13` or `r` (both GIF sources) |
| `VAPID_SUBJECT` | `BUNNY_API` | Contact shown to push services |
| `REMEMBER_KEY` | generated | Fernet key for "stay signed in" |
| `DATA_DIR` | `/data` | SQLite, VAPID keys; mount a volume here |
| `VERIFY_TLS` | `1` | `0` disables TLS verification towards the Bunny server |
| `JANITOR_SECONDS` | `300` | Interval of the cleanup/auto-wipe check |
| `SSE_MAX_AGE` | `300` | Live streams are renewed this often (seconds) |

## Repository layout

| Path | Content |
|---|---|
| `app.py` | The whole application: Flask routes, crypto, push, HTML/CSS/JS templates, service worker |
| `icons/` | PWA icons (`icon-192.png`, `icon-512.png`, `icon-maskable.png`, `favicon.ico`) |
| `Dockerfile`, `docker-compose.yml` | Container build and example deployment |
| `requirements.txt` | Flask, requests, gunicorn, cryptography |

## Security notes

- **Not end-to-end encrypted.** The server decrypts messages to serve them; encryption protects the stored data (SQLite) and nothing more. Transport security is HTTPS, provided by your reverse proxy.
- This is a hobby project for a small trusted group, not an audited messenger. There is no forward secrecy and no per-user keys: everyone with a valid Bunny login can read the room.
- Whoever controls the Bunny server can read `.bunnyc` and the attachments.
- Link previews are fetched server-side with SSRF protection (public addresses only, size and time limits); previews of images go through an in-memory proxy.
- The fake 502 screen is obscurity, not security.
- Messages are rendered with DOM APIs only (no `innerHTML`), and attachment and GIF references are validated on the server.

## Limitations

- One room, no private chats, no message editing.
- Settings (previews, GIF source, fake error screen) are per device.
- iOS does not support share-to-app, and push requires the app to be added to the home screen.
