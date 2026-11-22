# Bunny Tale

> **Disclaimer:** Due to ongoing health issues I am no longer able to concentrate on developing software by myself. This project is therefore **vibe-coded**: written together with an AI assistant (Claude) and directed, tested and run by me. It is not a demo or proof of concept. It exists because I need it: it fixes a real problem in my day-to-day life and is in daily use. Read the code and the security notes below with that in mind.

A small, self-hosted group chat in a single room, built as a PWA, with messages encrypted at rest. It runs on top of an existing **Bunny** file server (cutebunny.io): users sign in with their Bunny account, encryption keys and attachments live on that server, and this app only keeps encrypted rows in SQLite.

It is the sibling of *Bunny Interactive* (the file-manager web client) and shares its login conventions, dark theme and hardware-ID scheme. It does not modify or depend on Interactive's code.

## Features

- Single shared room, live updates over Server-Sent Events
- Text with basic markdown (bold, italic, strike, inline/fenced code, quotes, lists, links)
- Photos, videos, audio and files, voice messages (record, listen, send), share-to-app from the system share sheet
- GIF picker with GIPHY and/or Klipy (optional, per-user choice)
- Search over all messages, jump to any message (older ones are loaded on demand)
- Edit your own messages (button, or long-press on mobile); edited messages are marked
- Offline-tolerant sending: on a poor connection messages are queued, shown as pending, and sent when the connection returns
- Replies (also by swiping), hearts, delete own messages, nicknames, link previews and tap-to-load embeds
- Message sound while the app is open (per-device switch in Settings)
- Opt-in web push notifications (own VAPID / RFC 8291 implementation, no third-party SDK)
- Alarms: wake another member ("Send alarm" in the attach menu, 30 s cooldown). It rings full screen in the Android app, or in the browser when they have no app; snooze (5 min, 10 min, 30 min or 1 h), dismiss and timeout (1:30) are posted to the chat
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

**Search and jump.** `GET /search` decrypts messages on the server and matches text and attachment names (case-insensitive, at least 2 characters, 30 results per page). `GET /messages?before=X&until=Y` returns everything from message Y up to X in one response, so jumping to an old message needs one request, not a page-by-page crawl.

**Editing.** `POST /edit` (own messages only) re-encrypts the body under the message's existing key and stores an edit timestamp; the old ciphertext is zeroed (`secure_delete`, WAL checkpoint). Clients update live through an `edit` event.

**Outbox.** Every message is queued in the browser (`localStorage`, survives reloads) and sent in order with a client-generated id. The server remembers the last 500 ids per sender (in memory), so a retry after a lost response returns the original message instead of posting a duplicate. Network errors, timeouts (20 s), 5xx and the post-wipe lock keep the message pending with backoff (3 s up to 30 s); definitive errors drop it with a notice. Edits and deletes need a connection and are not queued.

**Push and presence.** A page that is in front of the user sends a heartbeat every 20 s (`/presence`); the Android app also reports when it goes to the background. Pushes skip users with a heartbeat from a visible page in the last 50 s (any of their devices). The app additionally never shows a message notification while the chat is on screen. Server logs show every decision (`[push]`, `[fcm]` lines).

**Alarms.** `POST /alarm/send` creates an alarm in memory (one per woken member, 30 s cooldown per sender). If the member has the Android app registered, it goes only there via FCM (looping alarm sound, full-screen activity over the lock screen); otherwise it goes to their open browsers (SSE) plus a web push. The device reports `ring`, then `snooze` / `dismiss` / `timeout`; the app answers with a per-alarm token, so it needs no cookies. A snooze rings again after the chosen time (5, 10, 30 or 60 minutes). If no device answers, the server ends it itself (`timeout`, or `missed` when nothing ever rang). Alarms are lost on a server restart.

**Wipe.** Deletes all rows and attachments, removes `.bunnyc`, runs `VACUUM` (SQLite runs with `secure_delete`), and locks writing for 5 seconds. A janitor thread does the same after `AUTOWIPE_HOURS` without activity.

**Concurrency.** One gunicorn worker with 128 threads: sessions and live subscribers are held in memory, and each open chat holds one thread for its SSE stream. Do not raise the worker count.

## Deployment

Everything is configured through **environment variables**; `docker-compose.yml` needs no editing. Variables come from the shell, your CI/CD settings or a `.env` file next to the compose file (`.env` is git-ignored). `HWID_SALT` and `SECRET_KEY` are required: Compose refuses to start without them.

```bash
git clone https://github.com/lyvielle/bunny-tale
cd bunny-tale
printf 'HWID_SALT=...\nSECRET_KEY=...\n' > .env
docker compose up -d --build
```

The app listens on port 8000 inside the container. Compose publishes it on the host as `BIND_ADDR:HOST_PORT`:

| Variable | Default | Purpose |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0` | Host address to bind. Use `127.0.0.1` when a reverse proxy on the same host is the only client |
| `HOST_PORT` | `8001` | Host port to publish |
| `DATA_DIR` | `bunny-chat-data` | Host-side location of the persistent data (SQLite, keys), mounted at `/data`: a named Docker volume, or an absolute host path such as `/srv/bunny-tale` for a bind mount |

Convention: variables ending in `_DIR` are host-side mount locations read by Compose only; the paths inside the container are fixed and not configurable.

Put it behind a reverse proxy with HTTPS: service worker, microphone access, push and "install app" all require a secure context. For SSE, disable proxy buffering and allow long-lived responses.

### Application configuration (all passed through by `docker-compose.yml`)

| Variable | Default | Purpose |
|---|---|---|
| `BUNNY_API` | `https://cutebunny.io` | Bunny server base URL |
| `HWID_SALT` | **required** | Hardware-ID salt; **must equal Bunny Interactive's** |
| `SECRET_KEY` | **required** | Flask session signing key; keep it stable, or everyone is logged out on restart |
| `AUTOWIPE_HOURS` | `48` | Wipe after this long without activity (`0` = off) |
| `GIPHY_API_KEY` | – | Enables GIPHY in the GIF picker |
| `KLIPY_API_KEY` | – | Enables Klipy; set either, both or none |
| `GIPHY_RATING` | `pg-13` | `g`, `pg`, `pg-13` or `r` (both GIF sources) |
| `VAPID_SUBJECT` | `BUNNY_API` | Contact shown to push services |
| `FCM_SERVICE_ACCOUNT` | – | Firebase service-account JSON, as base64 (`base64 -w0 key.json`), or a path to the file. Enables push to the optional Android app |
| `REMEMBER_KEY` | generated | Fernet key for "stay signed in" |
| `VERIFY_TLS` | `1` | `0` disables TLS verification towards the Bunny server |
| `JANITOR_SECONDS` | `300` | Interval of the cleanup/auto-wipe check |
| `SSE_MAX_AGE` | `300` | Live streams are renewed this often (seconds) |

## Repository layout

| Path | Content |
|---|---|
| `app.py` | The whole application: Flask routes, crypto, push, HTML/CSS/JS templates, service worker |
| `sounds/` | `notification.wav`, the message sound (optional; without it the setting is hidden) |
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

- One room, no private chats.
- Only the text of a message can be edited, not its attachments.
- The retry protection is in memory: if the server restarts while a send is in doubt, an attachment message may be reported as failed although it arrived.
- Settings (previews, GIF source, fake error screen) are per device.
- iOS does not support share-to-app, and push requires the app to be added to the home screen.

## Optional Android app

The PWA/browser version is unaffected. For more reliable notifications on Android there is a small native wrapper in `android/` (WebView + Firebase Cloud Messaging; it just loads your server).

1. Create a free Firebase project, add an Android app with package `app.bunnytale`, download `google-services.json`.
2. Project settings → Service accounts → generate a private key; set `FCM_SERVICE_ACCOUNT` on the server to `base64 -w0 key.json` of that file.
3. Create a signing key once: `keytool -genkeypair -keystore release.jks -alias bunnytale -keyalg RSA -keysize 2048 -validity 36500` and keep it (updates must use the same key).
4. GitHub → Settings: secrets `GOOGLE_SERVICES_JSON`, `KEYSTORE_B64` (`base64 -w0 release.jks`), `KEYSTORE_PASSWORD`; variable `BUNNY_TALE_URL`.
5. Run the *Android app (optional)* workflow and install the APK from its artifacts. Enable *Notifications* in the app's settings.

The workflow is manual only. In the app, notifications go through FCM instead of Web Push. The app always registers for alarms, even with notifications off; logging out removes the registration. Android 8 or newer is required. On Android 14+, the app asks once for the *full-screen notifications* permission, which full-screen alarms need. The attach buttons offer the camera (photo / video) next to the file and gallery pickers.
