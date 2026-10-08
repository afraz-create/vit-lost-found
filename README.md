# 🎓 VIT Campus Lost & Found Recovery Portal

A full-stack replacement for messy WhatsApp groups. Students report lost/found items at official VIT venues, owners are verified through a private challenge, and returns are coordinated at safe campus checkpoints, with no public phone numbers.

**Stack:** Node.js · Express · SQLite (better-sqlite3) · bcryptjs · vanilla JS single-page frontend.

## Features
- **Separate Lost / Found feeds** with search, category and venue filters
- **Official venues only:** SJT, TT, PRP, SMV, MB, GDN, CDMM · MH-A…MH-T · LH-A…LH-J · Gazebo, Food Mall, DC · Central Library · Sports Complex
- **Categories:** ID Cards, Room Keys, Calculators, Lab Equipment, Earphones, Wallets
- **Privacy:** the public API never returns poster id, registration number, email or phone. Claimants and posters appear to each other only as "Poster" / "Claimant #id". Chat blocks phone-number sharing.
- **Claim Verification Request:** claimant answers the poster's custom challenge. The poster approves or rejects in a private dashboard.
- **Private handoff thread** (approved claims only) with official checkpoint picker (e.g. SJT Ground Floor Reception, Central Library Security Desk)
- **Lifecycle:** either party can mark an item **Resolved**, which removes it from the active board
- **Auth:** email OTP verification at signup, forgot/reset password via emailed code, bcrypt (cost 12), HttpOnly session cookie that expires after 7 days (`Secure` in production), rate limiting, 15-minute account lockout after 5 wrong passwords
- **UX:** scrollytelling landing page, loading skeletons, empty states, submit/disabled states, toasts, inline validation errors (client and server)

## Local setup
Requires Node.js 18+.

```bash
git clone <your-repo-url> vit-lost-found
cd vit-lost-found
npm install
npm run db:init      # creates lostfound.db from schema.sql + demo data
npm start            # http://localhost:3000
```

- Schema only (no demo data): `SEED=0 npm run db:init`
- Custom port / DB file: `PORT=4000 DB=./my.db npm start`
- Demo logins (after seeding): `25BCE0000` / `LF000` and `22BIT1002` / `Demo@1234`

## Authentication & email setup
- Sign-up creates an **unverified** account and emails a 6-digit code (10-minute expiry, 5 tries, 60s resend cooldown). Unverified users cannot log in.
- **Forgot password** emails a reset code. Resetting signs the user out everywhere. The API never reveals whether an email is registered.
- **Development (default):** if no SMTP is configured, codes are printed in the server terminal as `[DEV MAIL]`, so nothing extra is needed to test.
- **Real email:** set these before `npm start`:
  ```bash
  SMTP_HOST=smtp.gmail.com SMTP_PORT=587 SMTP_USER=you@gmail.com SMTP_PASS=app-password MAIL_FROM="VIT Lost & Found <you@gmail.com>" npm start
  ```
  (Gmail needs an App Password. Use `SMTP_SECURE=1` with port 465.)
- **Production:** run with `NODE_ENV=production` behind HTTPS so the session cookie is marked `Secure`.
- Existing databases are migrated automatically on start, and users from before this change are treated as verified.
- Seeded demo users are already verified. New sign-ups must verify.

## Extra features
- **Email alerts:** owners are emailed when a claim arrives and claimants when it is approved or rejected (emails never reveal who the other person is). Without SMTP they print in the terminal.
- **Instant private chat:** messages arrive live over Server-Sent Events (falls back to polling).
- **Report and moderation:** any user can report a listing. Users whose registration number is in `ADMIN_REG_NOS` get an **Admin** page to remove listings or dismiss reports (in development the default admin is `25BCE0000`; in production set `ADMIN_REG_NOS` explicitly). See `.env.example`.
- **Campus photos:** `public/img/` holds the home-page hero (`hero.jpg`) and MB (Dr. M.G.R. Block), SJT, TT, PRP and Central Library photos. They appear in the home gallery, on listing details for those venues, and in the private thread when one of those checkpoints is chosen. Replace any file to change it. If `hero.jpg` is removed, the animated gradient is used.

## Try the full flow
1. Log in as `25BCE0000`, open the **Found** tab, and note the listings.
2. Log out, log in as `22BIT1002`, open a found item and submit a claim answer.
3. Log back in as `25BCE0000` → **My Dashboard → Claims to review** → Approve.
4. Both users open **Private thread**, chat, choose a checkpoint, then **Mark Resolved**.

## Project structure
```
server.js          Express API + validation + privacy rules
schema.sql         Database tables
scripts/init-db.js Bootstrap + seed script
public/index.html  Frontend (SPA, scrollytelling)
```

## API summary
| Method | Route | Purpose |
|---|---|---|
| POST | /api/register, /api/verify, /api/resend | Sign-up with email OTP |
| POST | /api/login, /api/logout | Auth (lockout + rate limits) |
| POST | /api/forgot, /api/reset | Password reset by emailed code |
| GET | /api/meta, /api/me | Venues/categories/checkpoints, current user |
| GET/POST | /api/items | Public feed (masked) / create listing |
| POST | /api/items/:id/claims | Claim Verification Request |
| GET | /api/dashboard | Own listings, claims received, claims sent |
| POST | /api/claims/:id/decision | approve / reject |
| GET/POST | /api/claims/:id/thread, /messages, /meetup | Private handoff |
| POST | /api/items/:id/resolve | Mark resolved |

## Notes
- Listing photos are optional uploads (resized client-side and stored in SQLite). Category illustrations use emoji so the site works offline. To add real campus photos, drop them in `public/img/` and reference them in the hero CSS.
- Before production, serve over HTTPS and add `Secure` to the session cookie and rate limiting on `/api/login`.

## Known limitations
- Listing photos are stored in SQLite as small compressed images, which is fine for a campus pilot but not for large scale.
- Chat uses one server process (in-memory event bus); running several server instances needs a shared bus such as Redis.
- Moderation is report-driven. There is no automatic content filtering.
- SQLite suits a single-server deployment. Switch to PostgreSQL for heavy traffic.
