# Andromina's Secret Inbox 💌

Share your link → friends send anonymous messages → you read them at `/admin`.

- **Public page:** `/`  (nice link preview for WhatsApp / Instagram / X / iMessage)
- **Dashboard:** `/admin`  (phone + PIN; change PIN from inside the dashboard)
- No database to set up: messages are stored in a file. Zero npm dependencies.

## Deploy on Railway (≈3 minutes)
1. Push this folder to a GitHub repo.
2. railway.app → **New Project → Deploy from GitHub repo** → pick it.
3. **Settings → Networking → Generate Domain** (this is your share link).
4. **Add a Volume** to the service and mount it at `/data` (keeps messages & your PIN across redeploys).
   Without this, messages are lost whenever Railway redeploys.

5. **Variables tab → add `ADMIN_PHONE` and `ADMIN_PIN`** (your dashboard login). No credentials live in the code or on GitHub.
   They're read on first start only; after that, change the PIN from the dashboard.

Optional: `OWNER_NAME`, `BASE_URL` (custom domain in link previews).

Run locally: copy `.env.example` to `.env`, fill it in, then `node server.js` → http://localhost:3000
