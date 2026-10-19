# Secure login backend

This starter project stores registered account identifiers and **bcrypt password hashes** in SQLite. It does not store raw passwords or secretly collect credentials.

## Run locally
1. Install Node.js 20 or newer.
2. In this folder, run `npm install`.
3. Copy `.env.example` to `.env` and replace `SESSION_SECRET` with a long random secret.
4. Put your login page in `public/` as `index.html` (or rename `Log In.html` to `index.html`).
5. Run `npm start`.
6. Open `http://localhost:3000`.

The included login page should use `API_BASE = ''` when served from this backend, so requests go to the same origin.

## API
- `POST /register` with JSON `{ "identifier": "you@example.com", "password": "a-long-password" }`
- `POST /login` with the same JSON shape
- `GET /me` to check the current session
- `POST /logout` to end the session

Registration is what creates/stores an account. A login attempt should only verify credentials against an existing account. To add registration to your site, create a separate sign-up form that calls `/register`.

## Before public deployment
- Use HTTPS and set `NODE_ENV=production`.
- Set a strong, unique `SESSION_SECRET` in the hosting provider's environment settings; do not commit `.env`.
- Configure backups, access controls, monitoring, and a production-grade persistent session store.
- Add email verification, password reset, and privacy/retention policies as appropriate.
- Do not use this starter as a clone of a third-party login page or to collect credentials for a service you do not own or administer.
