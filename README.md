# 🕰️ Time Capsule CLI

> Write encrypted messages to your future self. Seal them with AES-256-GCM, lock them until a chosen date, and let a trusted RFC 3161 timestamp prove exactly when they were sealed.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Click](https://img.shields.io/badge/CLI-Click-black?style=flat-square)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-orange?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## What It Does

Write a message today. Lock it until a future date. Nobody — not even you — can open it before then. When the date arrives, decrypt it and read what past-you wanted future-you to know.

```bash
capsule write "Dear future me, I hope you finally shipped that startup." \
  --unlock 2027-06-01 --tag career --mood hopeful
```

---

## Features

- 🔐 **AES-256-GCM Encryption** — Military-grade encryption with a locally-stored master key
- ⏳ **Time-Locked** — Capsules cannot be decrypted before their unlock date, enforced cryptographically
- 🕰️ **RFC 3161 Trusted Timestamps** — Cryptographic proof of *when* a capsule was actually sealed, verified against a trusted timestamp authority
- 😊 **Mood Tracking** — Tag each capsule with how you're feeling (hopeful, excited, nostalgic, anxious, proud, and more)
- 🏷️ **Custom Tags** — Organize capsules by category (career, relationships, goals, etc.)
- 📊 **Stats Dashboard** — Mood distribution bar chart and capsule history
- 📦 **Export/Backup** — Export all capsules as a zip archive
- 🔄 **Optional Git Sync** — Auto-commit and push sealed capsules to a private git remote (master key is never committed)
- 🎨 **Rich Terminal UI** — Beautiful tables, panels, and spinners via `rich`
- 🛡️ **Tamper Detection** — GCM auth tags detect any corruption or tampering on open

---

## Installation

```bash
git clone https://github.com/kulatshreeram/Time-Capsule-CLI-.git
cd Time-Capsule-CLI-
pip install -r requirements.txt
pip install -e .
```

---

## Usage

### Write a capsule
```bash
capsule write "Hello future me!" --unlock 2027-06-01 --tag career --mood hopeful

# Or omit the message to open your $EDITOR for longer entries
capsule write --unlock 2030-01-01
```

### List all capsules
```bash
capsule list
```
Shows ID, unlock date, mood, and tags in a Rich table — message content stays hidden until unlocked.

### Open a capsule
```bash
capsule open <capsule-id>
```
Decrypts and displays the message if the unlock date has passed. Otherwise shows a countdown.

```bash
capsule open <capsule-id> --skip-verify   # skip RFC 3161 timestamp check
```

### View stats
```bash
capsule stats
```
Mood distribution chart and capsule history at a glance.

### Export a backup
```bash
capsule export --output ~/timecapsule-backup.zip
```

### Enable Git sync
```bash
capsule init --git git@github.com:you/private-capsules.git
```
Every future `capsule write` auto-commits and pushes. The master encryption key is **never** committed — a `.gitignore` is generated automatically.

---

## How It Works

1. **Encryption** — Each message is serialized as JSON (`message`, `mood`, `tags`, `unlock_timestamp`) and encrypted with AES-256-GCM using a per-capsule random nonce.
2. **Key Storage** — A 32-byte master key is generated on first use and stored at `~/.timecapsule/master.key` with restrictive file permissions (`chmod 600` on Unix, `icacls` lockdown on Windows).
3. **Time Lock** — Decryption is blocked in code until the system clock passes `unlock_timestamp`. Attempting early access raises a `CapsuleLockedError` with a live countdown.
4. **Trusted Timestamping** — On write, an RFC 3161 timestamp token is requested from a Timestamp Authority, cryptographically proving the capsule existed at that moment — preventing backdating.
5. **Tamper Protection** — AES-GCM's authentication tag ensures any modification to the ciphertext is detected on decrypt.

---

## Tech Stack

| Library | Purpose |
|---------|---------|
| `click` | CLI framework & commands |
| `cryptography` | AES-256-GCM encryption |
| `rfc3161ng` | Trusted timestamp requests & verification |
| `rich` | Terminal tables, panels, progress spinners |
| `gitpython` | Optional git auto-sync |
| `pytest` / `pytest-mock` | Test suite |

---

## Project Structure

```
Time-Capsule-CLI-/
├── cli.py            # Click CLI entrypoint — write, list, open, export, stats, init
├── encrypt.py         # AES-256-GCM encryption/decryption + key management
├── storage.py         # Capsule persistence & index management
├── timestamp.py        # RFC 3161 trusted timestamp request/verify
├── git_sync.py        # Optional git auto-commit/push
├── test_cli.py
├── test_encrypt.py
└── test_storage.py
```

---

## Where Your Data Lives

```
~/.timecapsule/
├── master.key        # Your encryption key (chmod 600, never commit this)
├── index.json         # Capsule metadata index
├── capsules/           # Encrypted .capsule files
└── .gitignore          # Auto-generated to protect master.key
```

---

## License

MIT © [kulatshreeram](https://github.com/kulatshreeram)
