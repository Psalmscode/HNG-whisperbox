# WhisperBox — E2EE Messaging Client

A fully client-side encrypted messaging frontend for the WhisperBox API.

## Setup

```bash
npm install
npm run dev
```

Then open http://localhost:5173

## How it works

- RSA-OAEP 2048-bit keypair generated in-browser on registration
- Private key exported as **PKCS8** and wrapped with **AES-KW** (derived via PBKDF2 from your password)
- Messages encrypted with AES-GCM-256; the symmetric key is RSA-encrypted for both recipient and sender
- Private key lives only in memory — never persisted to localStorage or disk
- Real-time delivery via WebSocket with automatic token refresh
