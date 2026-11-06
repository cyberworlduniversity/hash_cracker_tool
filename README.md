# 🔓 Hash Cracker Tool


## Get this repository

Clone the current project (this repository's canonical GitHub URL), then follow the installation and usage steps below.

```bash
git clone https://github.com/cyberworlduniversity/hash_cracker_tool.git
cd hash_cracker_tool
```

> **Educational Use Only** — This tool is designed for learning about cryptographic hashing, password security, and ethical cybersecurity concepts. Only use it on hashes you own or have explicit permission to test.

---

## 📖 Table of Contents

1. [What Is a Hash?](#what-is-a-hash)
2. [Definitions & Key Concepts](#definitions--key-concepts)
3. [Supported Hash Algorithms](#supported-hash-algorithms)
4. [Attack Methods Explained](#attack-methods-explained)
5. [Full Program Flow](#full-program-flow)
6. [Learning Procedure](#learning-procedure)
7. [Installation & Requirements](#installation--requirements)
8. [Usage Guide](#usage-guide)
9. [Output Examples](#output-examples)
10. [Security Lessons](#security-lessons)

---

## 🧠 What Is a Hash?

A **cryptographic hash function** is a one-way mathematical algorithm that transforms any input (called *plaintext*) into a fixed-length string (called a *digest* or *hash*). Key properties:

| Property | Description |
|---|---|
| **Deterministic** | Same input always produces the same hash |
| **One-way** | Cannot reverse a hash to get original input |
| **Avalanche effect** | Tiny input change = completely different hash |
| **Fixed-length output** | Regardless of input size |

**Example:**
```
Input:   "password"
MD5:     5f4dcc3b5aa765d61d8327deb882cf99
SHA-256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

---

## 📚 Definitions & Key Concepts

### 🔑 Hash
A fixed-length hexadecimal string output produced by a hash algorithm. Cannot be reversed mathematically.

### 🔑 Plaintext
The original, human-readable password or data before hashing (e.g., `"mypassword"`).

### 🔑 Digest
Another name for the hash output — the result of running data through a hash function.

### 🔑 Collision
When two different inputs produce the same hash output. This is considered a vulnerability in older algorithms like MD5.

### 🔑 Dictionary Attack
An attack that tries every word from a pre-built list (wordlist/dictionary) against a hash. Fast and effective against weak/common passwords.

### 🔑 Brute-Force Attack
An exhaustive attack that tries every possible combination of characters up to a given length. Guaranteed to crack but exponentially slower as length increases.

### 🔑 Rainbow Table
A precomputed table of hashes → passwords. Much faster than dictionary attacks but requires massive storage. Countered by **salting**.

### 🔑 Salt
A random value added to a password before hashing. Makes identical passwords produce different hashes, defeating rainbow tables. Example: `hash("password" + "x7kQ2!") ≠ hash("password")`.

### 🔑 Wordlist / Dictionary
A text file containing common passwords, words, or phrases — one per line. Famous examples: `rockyou.txt` (14 million passwords from a real data breach).

### 🔑 Hash Identification
The process of detecting which algorithm was used to produce a hash, typically by examining its character length.

### 🔑 Charset
The set of characters used in brute-force attacks (e.g., `a-z`, `0-9`, symbols).

### 🔑 Candidate
A word or combination being tested during an attack.

### 🔑 Cryptanalysis
The mathematical study of breaking cryptographic algorithms.

### 🔑 Hash Cracking
The process of finding the original plaintext that produces a given hash — either through dictionary, brute-force, or rainbow table methods.

### 🔑 Encoding
Converting a string to bytes. Python uses UTF-8 or Latin-1 encoding when hashing text.

---

## 🔒 Supported Hash Algorithms

| Algorithm | Hash Length (chars) | Status | Notes |
|---|---|---|---|
| **MD5** | 32 | ⚠️ Broken | Fast but cryptographically weak |
| **SHA-1** | 40 | ⚠️ Deprecated | Collision attacks demonstrated |
| **SHA-224** | 56 | ✅ Secure | SHA-2 family |
| **SHA-256** | 64 | ✅ Secure | Widely used standard |
| **SHA-384** | 96 | ✅ Secure | SHA-2 family |
| **SHA-512** | 128 | ✅ Secure | Strongest in this tool |

---

## ⚔️ Attack Methods Explained

### 1. Dictionary Attack
```
Target Hash ──► Load Wordlist ──► Hash Each Word ──► Compare ──► Match? ✓/✗
```
- **Speed:** Very fast (depends on wordlist size)
- **Best for:** Common passwords, leaked credentials
- **Weakness:** Won't crack random/unique passwords
- **How it works:** Each word from the list is hashed and compared to the target. If they match, the word is the password.

### 2. Brute-Force Attack
```
Target Hash ──► Build Charset ──► Generate All Combos ──► Hash Each ──► Compare ──► Match? ✓/✗
```
- **Speed:** Slow — grows exponentially with length
- **Best for:** Short passwords (1–6 characters)
- **Certainty:** Will always find the answer if within the search space
- **Example:** For 6-char lowercase = 26⁶ = 308,915,776 combinations

### Complexity Chart (lowercase, SHA-256)
| Length | Combinations | Approx Time |
|---|---|---|
| 1 | 26 | Instant |
| 2 | 676 | Instant |
| 3 | 17,576 | < 1 second |
| 4 | 456,976 | ~1 second |
| 5 | 11,881,376 | ~30 seconds |
| 6 | 308,915,776 | ~15 minutes |
| 8 | 208,827,064,576 | Days |

---

## 🔄 Full Program Flow

```
┌─────────────────────────────────────────────────────────┐
│                    hash_cracker.py                       │
│                                                          │
│  ┌──────────┐    ┌──────────────────────────────────┐   │
│  │   CLI    │───►│  argparse – parse user command   │   │
│  │  Input   │    └──────────────┬───────────────────┘   │
│  └──────────┘                   │                        │
│                    ┌────────────▼────────────┐           │
│                    │  identify_hash()        │           │
│                    │  (detect algorithm by   │           │
│                    │   hash string length)   │           │
│                    └────────────┬────────────┘           │
│                                 │                        │
│         ┌───────────────────────▼───────────────────┐   │
│         │         compute_hash(word, algo)           │   │
│         │  Uses hashlib.new(algo, word.encode())     │   │
│         │  Returns hex digest string                 │   │
│         └────────────────┬──────────────────────────┘   │
│                          │                               │
│    ┌─────────────────────▼──────────────────────────┐   │
│    │              Attack Selection                   │   │
│    │                                                 │   │
│    │  ┌──────────────────┐  ┌───────────────────┐   │   │
│    │  │ dictionary_      │  │ brute_force_      │   │   │
│    │  │ attack()         │  │ attack()          │   │   │
│    │  │                  │  │                   │   │   │
│    │  │ 1. Open wordlist │  │ 1. Build charset  │   │   │
│    │  │ 2. For each line │  │ 2. itertools      │   │   │
│    │  │    hash the word │  │    .product()     │   │   │
│    │  │ 3. Try variants  │  │ 3. Hash combos    │   │   │
│    │  │    (lower/upper/ │  │ 4. Compare hash   │   │   │
│    │  │    capitalize)   │  │ 5. Return result  │   │   │
│    │  │ 4. Compare hash  │  └───────────────────┘   │   │
│    │  │ 5. Return result │                           │   │
│    │  └──────────────────┘                           │   │
│    └─────────────────────┬──────────────────────────┘   │
│                          │                               │
│              ┌───────────▼──────────┐                   │
│              │    Result Output     │                   │
│              │  success / failure   │                   │
│              │  password / attempts │                   │
│              │  elapsed time / algo │                   │
│              └──────────────────────┘                   │
└─────────────────────────────────────────────────────────┘
```

---

## 📘 Learning Procedure

This tool is structured as a **step-by-step learning journey** from concept to implementation:

### Step 1 — Understand Hashing
- Run `python hash_cracker.py generate --text "hello" --algo md5`
- Then try SHA-256: `python hash_cracker.py generate --text "hello" --algo sha256`
- Observe how the same word produces a completely different digest with different algorithms

### Step 2 — Identify Hashes
- Run `python hash_cracker.py identify --hash 5f4dcc3b5aa765d61d8327deb882cf99`
- The tool detects it's MD5 just from the 32-character length
- Practice with: `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` (SHA-256)

### Step 3 — Run the Demo
- Run `python hash_cracker.py demo`
- Watch the dictionary attack try each word from the sample wordlist
- Observe how "password" and "guitar" are found instantly

### Step 4 — Dictionary Attack
- Create a wordlist.txt with common passwords
- Generate a hash: `python hash_cracker.py generate --text "sunshine" --algo sha1`
- Crack it: `python hash_cracker.py dict --hash <paste_hash> --wordlist wordlist.txt`

### Step 5 — Brute-Force Attack
- Try: `python hash_cracker.py generate --text "ab" --algo md5`
- Then: `python hash_cracker.py brute --hash <paste_hash> --charset lowercase --max-len 3`
- Observe the exponential growth as you increase max-len

### Step 6 — Understand Defense
- Add a salt to your plaintext: `python hash_cracker.py generate --text "password+randomsalt123" --algo sha256`
- Try to crack it with the same wordlist — you won't succeed!
- This demonstrates why salting defeats dictionary attacks

### Step 7 — Batch Cracking
- Create a file `hashes.txt` with multiple hashes (one per line)
- Run: `python hash_cracker.py batch --hashes-file hashes.txt --wordlist wordlist.txt`

---

## ⚙️ Installation & Requirements

### Requirements
- Python 3.7+
- No external dependencies — uses only Python standard library

### Setup
```bash
# Clone or download the files
git clone https://github.com/cyberworlduniversity/hash_cracker_tool.git
cd hash_cracker_tool

# No installation needed — Python built-ins only
# Optional: make executable
chmod +x hash_cracker.py
```

### Optional: Download a Real Wordlist
```bash
# RockYou wordlist (14M passwords) — use responsibly
# Available on Kali Linux at: /usr/share/wordlists/rockyou.txt
```

---

## 📋 Usage Guide

```
usage: hash_cracker.py [-h] {generate,identify,dict,brute,batch,demo} ...

Commands:
  generate   Generate a hash from plaintext text
  identify   Identify the algorithm of a hash
  dict       Dictionary attack against a single hash
  brute      Brute-force attack against a single hash
  batch      Crack multiple hashes from a file
  demo       Run a quick demo with built-in sample wordlist
```

### Generate a Hash
```bash
python hash_cracker.py generate --text "mypassword" --algo sha256
```

### Identify a Hash
```bash
python hash_cracker.py identify --hash 5f4dcc3b5aa765d61d8327deb882cf99
```

### Dictionary Attack
```bash
python hash_cracker.py dict \
  --hash 5f4dcc3b5aa765d61d8327deb882cf99 \
  --wordlist wordlist.txt \
  --algo auto
```

### Brute-Force Attack
```bash
python hash_cracker.py brute \
  --hash 5f4dcc3b5aa765d61d8327deb882cf99 \
  --charset digits \
  --min-len 1 \
  --max-len 6
```

### Batch Crack Multiple Hashes
```bash
python hash_cracker.py batch \
  --hashes-file targets.txt \
  --wordlist rockyou.txt
```

### Run Demo
```bash
python hash_cracker.py demo
```

---

## 📤 Output Examples

### Successful Crack
```
============================================================
  Hash Cracker Tool v1.0.0
  Educational Use Only
============================================================

[*] Starting Dictionary Attack
    Hash      : 5f4dcc3b5aa765d61d8327deb882cf99
    Algorithm : MD5
    Wordlist  : wordlist.txt
    ──────────────────────────────────────────────────

[+] PASSWORD FOUND!
    Password  : password
    Attempts  : 1
    Time      : 0.001s
```

### Failed Crack
```
[-] Hash not cracked after 14,344,391 attempts (48.23s)
```

### Hash Generation
```
[*] Hash Generator
    Input     : mypassword
    Algorithm : SHA256
    Hash      : 89e01536ac207279409d4de1e5253e01ea85473516
```

---

## 🛡️ Security Lessons

### Why MD5 is Dangerous for Passwords
- MD5 was designed for speed — can compute **billions** of hashes/second on a GPU
- No salting = rainbow table attacks work perfectly
- **Never use MD5 to store passwords in production systems**

### Secure Password Storage (what you should use)
| Algorithm | Purpose | Notes |
|---|---|---|
| **bcrypt** | Password hashing | Built-in salt, deliberately slow |
| **Argon2** | Password hashing | Memory-hard, winner of PHC |
| **scrypt** | Password hashing | Memory and CPU intensive |
| **PBKDF2** | Key derivation | Used in WPA2, iOS |

### Defense Checklist
- ✅ Always salt passwords before hashing
- ✅ Use slow hashing algorithms (bcrypt, Argon2)
- ✅ Use long, random passwords (16+ characters)
- ✅ Use a password manager
- ✅ Enable multi-factor authentication (MFA)
- ❌ Never store plaintext passwords
- ❌ Never use MD5/SHA-1 for passwords

---

## ⚖️ Legal & Ethical Notice

This tool is provided **strictly for educational purposes**:
- ✅ Testing your own systems and passwords
- ✅ Cybersecurity coursework and CTF challenges
- ✅ Understanding how hash attacks work to build better defenses
- ❌ Do NOT use on systems, accounts, or data you don't own
- ❌ Unauthorized password cracking is illegal in most jurisdictions

---

## 📁 File Structure

```
hash_cracker/
├── hash_cracker.py       # Main tool — all cracking logic
├── sample_wordlist.txt   # Auto-generated demo wordlist (40 common passwords)
├── README.md             # This file — full documentation
└── requirements.txt      # No external dependencies
```

---

*Happy learning! 🔐 Stay ethical, stay curious.*
