# Coffre Fort — Secure Digital Vault

A secure client-server file storage system built in Python as part of the **GS15** cryptography module at UTT (Université de Technologie de Troyes). The project implements a full cryptographic pipeline — authentication, key exchange, and layered file encryption — from scratch, without relying on standard cryptographic libraries.

---

## Overview

**Coffre Fort** (French for "safe" or "strongbox") lets users securely upload and retrieve files through a server over a TCP connection. Every step of the communication is protected by a stack of cryptographic mechanisms implemented manually:

- **Zero-Knowledge Proof (ZKP)** authentication — proves identity without transmitting the password
- **Diffie-Hellman key exchange** — establishes a shared session key
- **Dual-layer file encryption** — RSA (per-user key pair) + COBRA (custom block cipher) on top
- **HMAC-authenticated messages** — all choices/commands sent over the session are encrypted and integrity-checked

---

## Features

- Secure user registration and login with ZKP-based authentication
- Automatic RSA key pair generation on first login (stored locally and on the server)
- File upload: files are RSA-encrypted with the user's public key and stored on the server
- File retrieval: files are re-encrypted with COBRA using the Diffie-Hellman session key before transmission, then decrypted locally
- Session commands are encrypted with a shared session key and authenticated with HMAC
- All cryptographic primitives implemented from scratch (no `cryptography`, `pycryptodome`, etc.)

---

## Cryptographic Architecture

### 1. Authentication — Zero-Knowledge Proof (ZKP)
The password is never sent in plaintext. Instead:
1. The password is hashed using a custom sponge hash function to derive a private key
2. The client computes a public commitment `M = g^r mod p`
3. The server sends a random challenge
4. The client responds with a proof derived from the challenge and their private key
5. The server verifies the proof — confirming identity without ever seeing the password

### 2. Session Key Exchange — Diffie-Hellman
After authentication, client and server perform a Diffie-Hellman exchange to derive a shared secret, which is used as the symmetric session key for all subsequent communication.

### 3. File Encryption — RSA
Uploaded files are encrypted server-side using the user's RSA public key (generated on first login). Only the user holds the private key to decrypt them.

### 4. Transfer Encryption — COBRA (custom block cipher)
When a file is retrieved, the server re-encrypts it using **SimpleCOBRA**, a custom 32-round block cipher operating on 16-byte blocks with:
- Key expansion (33 round keys derived via a custom hash)
- Substitution using generated S-boxes
- XOR round-key addition

The client decrypts with COBRA first, then RSA — effectively a double-decryption pipeline.

### 5. Message Integrity — HMAC
All session commands (file upload / file open choices) are encrypted with XOR using the session key and authenticated with a custom HMAC before sending.

---

## Project Structure

```
coffre_fort/
├── main_client.py       # Entry point for the client
├── main_server.py       # Entry point for the server
├── connect.py           # Core client/server logic and protocol flow
├── auth.py              # ZKP authentication + sponge hash
├── encryption.py        # RSA key generation, XOR cipher, HMAC
├── derivation.py        # Password-to-key derivation (sponge hash)
├── credentials.py       # User credential storage (JSON)
├── simplecobrafile.py   # Custom COBRA block cipher
└── credentials.json     # Stored user credentials (auto-generated)
```

---

## Usage

### Start the server

```bash
python3 main_server.py
```

The server listens on port **6000**.

### Start the client

```bash
python3 main_client.py
```

On first run, enter a username and password — the client will generate your RSA key pair automatically.

### Session commands

```
What do you want to do?
1. Upload a file
2. Open a file
Enter your choice (1 or 2):
```

- **Upload**: provide a local file path; the file is sent and encrypted on the server
- **Open**: lists available files; select one to decrypt and download it locally

---

## Requirements

- Python 3.8+
- No external cryptographic libraries (all primitives are custom-built)
- Network access between client and server (default IP: `25.15.154.124`, port `6000`)

---

## Context

This project was developed for the **cryptography module at UTT**. The goal was to understand and implement real cryptographic protocols from the ground up, including:

- Discrete logarithm-based Zero-Knowledge Proofs
- Diffie-Hellman key agreement
- RSA encryption with manual prime generation
- Block cipher design (substitution + key schedule)
- HMAC-based message authentication

---
