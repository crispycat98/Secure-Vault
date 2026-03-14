# 🔐 Secure Vault

A local password manager built in Python. No cloud, no subscriptions, no browser extension. Your passwords stay on your machine, encrypted, and the only way in is a color-grid pattern you draw.

---

## What it does

Instead of a master password, you authenticate by drawing a pattern across a 3×3 grid of colored circles — think Android pattern lock but with colors. Each user gets a randomly assigned color layout, so even the grid itself is unique to you.

Once you're in, you get a clean vault dashboard where you can store, reveal, copy, and delete credentials. Passwords are AES-encrypted using a key derived from your pattern — meaning if you don't know the pattern, the vault data is just noise.

---

## How the security actually works

- Your pattern sequence + a per-account random salt → run through **PBKDF2-HMAC-SHA256** (100,000 iterations) → becomes the AES encryption key
- That key is **never stored anywhere** — it only exists in memory during your session
- Vault passwords are encrypted with **Fernet (AES-128-CBC)** before hitting the database
- The pattern itself is stored as a sequence of cell indices — not the key, not anything reversible
- Signup password is **bcrypt-hashed** — it's not used for encryption, just account creation
- 3 wrong pattern attempts → account locked for 24 hours, persisted in the DB so restarting the app doesn't bypass it

If you forget your pattern, there's a **recovery code** — a 24-character code generated once at setup, bcrypt-hashed and stored. You use it to reset your pattern, and the vault gets re-encrypted under the new key automatically. The original recovery code stays valid across resets.

**One known limitation worth being upfront about:** the pattern keyspace is small. A 4-cell minimum across 9 cells gives at most ~3000 possible sequences. PBKDF2 with 100k iterations makes each guess expensive, but someone with your DB file and enough time could try all combinations. Using the maximum 9 cells significantly raises the bar. This is a tradeoff inherent to pattern-based auth — convenience vs. entropy.

---

## Stack

- Python 3.10+
- CustomTkinter — UI
- cryptography — Fernet + PBKDF2
- bcrypt — password and recovery code hashing
- SQLite — local database, no setup needed

---

## Setup

```bash
git clone https://github.com/yourusername/secure-vault
cd secure-vault
pip install -r requirements.txt
python login_app_v7.py
```

That's it. The database (`accounts.db`) gets created automatically next to the script on first run.

> If you're updating from an older version and the app crashes on launch, delete `accounts.db` — schema changes between versions aren't always backwards compatible.

---

## Features

- Color-grid pattern authentication (tap or drag)
- Per-user randomized grid layout
- AES-encrypted credential vault
- PBKDF2 key derivation — brute forcing the DB is not practical
- Live username availability check on signup
- Password strength indicator + random password generator
- Search credentials by site or username
- Reveal / copy / delete per entry
- 24-hour account lockout after 3 failed pattern attempts
- Recovery code system for forgotten patterns
- Session key wiped from memory on logout

---

## Screenshots



## What I'd add with more time

- Export vault to encrypted JSON
- Auto-clear clipboard after 30 seconds on copy
- Audit log — track login history per account
- Windows/macOS packaging so it runs as a standalone `.exe` / `.app`
