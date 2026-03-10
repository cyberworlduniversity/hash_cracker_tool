#!/usr/bin/env python3
"""
Hash Cracker Tool
=================
A Python tool that attempts to crack MD5 and SHA hashes using
dictionary attacks and brute-force methods.

Author: Hash Cracker Tool
Version: 1.0.0
"""

import hashlib
import itertools
import string
import time
import sys
import os
import argparse
from pathlib import Path


# ─────────────────────────────────────────────
#  SECTION 1: HASH IDENTIFICATION
# ─────────────────────────────────────────────

HASH_LENGTHS = {
    32:  "MD5",
    40:  "SHA-1",
    56:  "SHA-224",
    64:  "SHA-256",
    96:  "SHA-384",
    128: "SHA-512",
}

def identify_hash(hash_str: str) -> str:
    """Identify the hash algorithm based on hash length."""
    h = hash_str.strip().lower()
    length = len(h)
    return HASH_LENGTHS.get(length, f"Unknown (length={length})")


# ─────────────────────────────────────────────
#  SECTION 2: HASH COMPUTATION
# ─────────────────────────────────────────────

def compute_hash(plaintext: str, algorithm: str) -> str:
    """
    Compute a hash of the plaintext using the specified algorithm.

    Parameters
    ----------
    plaintext : str  – The word/phrase to hash
    algorithm : str  – One of: md5, sha1, sha224, sha256, sha384, sha512

    Returns
    -------
    str – Hex-encoded digest
    """
    algo = algorithm.lower().replace("-", "")
    encodings = ["utf-8", "latin-1"]
    for enc in encodings:
        try:
            data = plaintext.encode(enc)
            break
        except UnicodeEncodeError:
            continue
    else:
        data = plaintext.encode("utf-8", errors="replace")

    h = hashlib.new(algo, data)
    return h.hexdigest()


def detect_algorithm(hash_str: str) -> str:
    """Map a hash string to its most likely hashlib algorithm name."""
    mapping = {
        32:  "md5",
        40:  "sha1",
        56:  "sha224",
        64:  "sha256",
        96:  "sha384",
        128: "sha512",
    }
    return mapping.get(len(hash_str.strip()), "md5")


# ─────────────────────────────────────────────
#  SECTION 3: DICTIONARY ATTACK
# ─────────────────────────────────────────────

def dictionary_attack(target_hash: str, wordlist_path: str,
                      algorithm: str = "auto") -> dict:
    """
    Attempt to crack a hash using a wordlist (dictionary attack).

    Flow
    ----
    1. Detect algorithm from hash length (or use supplied value)
    2. Open wordlist line-by-line (memory efficient)
    3. Hash each candidate word
    4. Compare against target hash
    5. Return result dict with status, matched word, attempts, elapsed time

    Parameters
    ----------
    target_hash   : str  – The hash to crack
    wordlist_path : str  – Path to the dictionary/wordlist file
    algorithm     : str  – Hash algorithm or 'auto' for auto-detection

    Returns
    -------
    dict with keys: success, password, attempts, elapsed, algorithm
    """
    target = target_hash.strip().lower()
    if algorithm == "auto":
        algorithm = detect_algorithm(target)

    if not os.path.exists(wordlist_path):
        return {
            "success": False,
            "password": None,
            "attempts": 0,
            "elapsed": 0,
            "algorithm": algorithm,
            "error": f"Wordlist not found: {wordlist_path}"
        }

    start = time.time()
    attempts = 0

    print(f"\n[*] Starting Dictionary Attack")
    print(f"    Hash      : {target}")
    print(f"    Algorithm : {algorithm.upper()}")
    print(f"    Wordlist  : {wordlist_path}")
    print(f"    {'─'*50}")

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.rstrip("\n\r")
                candidates = [word, word.lower(), word.upper(),
                              word.capitalize(), word.strip()]
                for candidate in candidates:
                    attempts += 1
                    if compute_hash(candidate, algorithm) == target:
                        elapsed = time.time() - start
                        print(f"\n[+] PASSWORD FOUND!")
                        print(f"    Password  : {candidate}")
                        print(f"    Attempts  : {attempts:,}")
                        print(f"    Time      : {elapsed:.3f}s")
                        return {
                            "success": True,
                            "password": candidate,
                            "attempts": attempts,
                            "elapsed": elapsed,
                            "algorithm": algorithm
                        }

                    if attempts % 50000 == 0:
                        print(f"    Progress  : {attempts:,} attempts... "
                              f"({time.time()-start:.1f}s)", end="\r")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user.")

    elapsed = time.time() - start
    print(f"\n[-] Hash not cracked after {attempts:,} attempts ({elapsed:.2f}s)")
    return {
        "success": False,
        "password": None,
        "attempts": attempts,
        "elapsed": elapsed,
        "algorithm": algorithm
    }


# ─────────────────────────────────────────────
#  SECTION 4: BRUTE-FORCE ATTACK
# ─────────────────────────────────────────────

def brute_force_attack(target_hash: str, algorithm: str = "auto",
                       charset: str = "lowercase",
                       min_length: int = 1,
                       max_length: int = 6) -> dict:
    """
    Attempt to crack a hash using brute-force (exhaustive) search.

    Flow
    ----
    1. Build the character set based on charset parameter
    2. Iterate all combinations from min_length to max_length
    3. For each candidate string, compute its hash
    4. Compare against target hash
    5. Return result dict

    Parameters
    ----------
    target_hash : str  – The hash to crack
    algorithm   : str  – Hash algorithm or 'auto'
    charset     : str  – 'lowercase', 'uppercase', 'digits', 'alphanumeric', 'all'
    min_length  : int  – Minimum password length to try
    max_length  : int  – Maximum password length to try (⚠ large = slow)

    Returns
    -------
    dict with keys: success, password, attempts, elapsed, algorithm
    """
    CHARSETS = {
        "lowercase":    string.ascii_lowercase,
        "uppercase":    string.ascii_uppercase,
        "digits":       string.digits,
        "alphanumeric": string.ascii_letters + string.digits,
        "all":          string.ascii_letters + string.digits + string.punctuation,
    }

    chars = CHARSETS.get(charset, string.ascii_lowercase)
    target = target_hash.strip().lower()
    if algorithm == "auto":
        algorithm = detect_algorithm(target)

    start = time.time()
    attempts = 0

    print(f"\n[*] Starting Brute-Force Attack")
    print(f"    Hash      : {target}")
    print(f"    Algorithm : {algorithm.upper()}")
    print(f"    Charset   : {charset} ({len(chars)} chars)")
    print(f"    Lengths   : {min_length} – {max_length}")
    print(f"    {'─'*50}")

    try:
        for length in range(min_length, max_length + 1):
            total = len(chars) ** length
            print(f"    Testing length {length} ({total:,} combinations)...")
            for combo in itertools.product(chars, repeat=length):
                candidate = "".join(combo)
                attempts += 1
                if compute_hash(candidate, algorithm) == target:
                    elapsed = time.time() - start
                    print(f"\n[+] PASSWORD FOUND!")
                    print(f"    Password  : {candidate}")
                    print(f"    Attempts  : {attempts:,}")
                    print(f"    Time      : {elapsed:.3f}s")
                    return {
                        "success": True,
                        "password": candidate,
                        "attempts": attempts,
                        "elapsed": elapsed,
                        "algorithm": algorithm
                    }
                if attempts % 100000 == 0:
                    print(f"    Progress  : {attempts:,} attempts...", end="\r")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user.")

    elapsed = time.time() - start
    print(f"\n[-] Hash not cracked after {attempts:,} attempts ({elapsed:.2f}s)")
    return {
        "success": False,
        "password": None,
        "attempts": attempts,
        "elapsed": elapsed,
        "algorithm": algorithm
    }


# ─────────────────────────────────────────────
#  SECTION 5: HASH GENERATOR (UTILITY)
# ─────────────────────────────────────────────

def generate_hash(plaintext: str, algorithm: str = "md5") -> str:
    """Generate a hash from a plaintext string (utility / testing)."""
    result = compute_hash(plaintext, algorithm)
    print(f"\n[*] Hash Generator")
    print(f"    Input     : {plaintext}")
    print(f"    Algorithm : {algorithm.upper()}")
    print(f"    Hash      : {result}")
    return result


# ─────────────────────────────────────────────
#  SECTION 6: BATCH CRACKING
# ─────────────────────────────────────────────

def batch_crack(hashes_file: str, wordlist_path: str,
                algorithm: str = "auto") -> list:
    """
    Crack multiple hashes from a file using dictionary attack.

    Parameters
    ----------
    hashes_file   : str – Path to file containing one hash per line
    wordlist_path : str – Path to wordlist
    algorithm     : str – Hash algorithm or 'auto'

    Returns
    -------
    list of result dicts
    """
    if not os.path.exists(hashes_file):
        print(f"[!] Hashes file not found: {hashes_file}")
        return []

    with open(hashes_file, "r") as f:
        hashes = [line.strip() for line in f if line.strip()]

    print(f"\n[*] Batch Cracking {len(hashes)} hash(es)...")
    results = []
    for i, h in enumerate(hashes, 1):
        print(f"\n--- Hash {i}/{len(hashes)} ---")
        res = dictionary_attack(h, wordlist_path, algorithm)
        results.append({"hash": h, **res})

    cracked = sum(1 for r in results if r["success"])
    print(f"\n[=] Batch Summary: {cracked}/{len(hashes)} cracked")
    return results


# ─────────────────────────────────────────────
#  SECTION 7: BUILT-IN SAMPLE WORDLIST
# ─────────────────────────────────────────────

SAMPLE_WORDLIST = [
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "dragon",
    "master", "sunshine", "princess", "welcome", "shadow",
    "hello", "root", "toor", "pass", "test", "guest",
    "superman", "batman", "iloveyou", "trustno1", "hunter2",
    "summer", "winter", "spring", "autumn", "football",
    "baseball", "soccer", "hockey", "guitar", "music",
    "love", "god", "jesus", "michael", "jessica",
]

def create_sample_wordlist(path: str = "sample_wordlist.txt"):
    """Write a small built-in sample wordlist to disk for demo purposes."""
    with open(path, "w") as f:
        f.write("\n".join(SAMPLE_WORDLIST))
    print(f"[*] Sample wordlist saved to: {path}")
    return path


# ─────────────────────────────────────────────
#  SECTION 8: CLI ENTRY POINT
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hash_cracker",
        description="Hash Cracker – Dictionary & Brute-Force Attack Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a hash for testing
  python hash_cracker.py generate --text "password" --algo md5

  # Dictionary attack
  python hash_cracker.py dict --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist wordlist.txt

  # Brute-force attack (short passwords)
  python hash_cracker.py brute --hash 5f4dcc3b5aa765d61d8327deb882cf99 --max-len 8 --charset digits

  # Identify a hash
  python hash_cracker.py identify --hash 5f4dcc3b5aa765d61d8327deb882cf99

  # Demo with built-in sample wordlist
  python hash_cracker.py demo
        """
    )
    sub = parser.add_subparsers(dest="command")

    # generate
    gen = sub.add_parser("generate", help="Generate a hash from plaintext")
    gen.add_argument("--text", required=True, help="Plaintext to hash")
    gen.add_argument("--algo", default="md5",
                     choices=["md5","sha1","sha224","sha256","sha384","sha512"],
                     help="Hash algorithm (default: md5)")

    # identify
    ident = sub.add_parser("identify", help="Identify hash algorithm by length")
    ident.add_argument("--hash", required=True, help="Hash string to identify")

    # dict
    da = sub.add_parser("dict", help="Dictionary attack")
    da.add_argument("--hash", required=True, help="Target hash")
    da.add_argument("--wordlist", required=True, help="Path to wordlist file")
    da.add_argument("--algo", default="auto", help="Algorithm (default: auto)")

    # brute
    bf = sub.add_parser("brute", help="Brute-force attack")
    bf.add_argument("--hash", required=True, help="Target hash")
    bf.add_argument("--algo", default="auto", help="Algorithm (default: auto)")
    bf.add_argument("--charset", default="lowercase",
                    choices=["lowercase","uppercase","digits","alphanumeric","all"],
                    help="Character set (default: lowercase)")
    bf.add_argument("--min-len", type=int, default=1, help="Min password length")
    bf.add_argument("--max-len", type=int, default=6, help="Max password length")

    # batch
    bt = sub.add_parser("batch", help="Crack multiple hashes from a file")
    bt.add_argument("--hashes-file", required=True, help="File with one hash per line")
    bt.add_argument("--wordlist", required=True, help="Path to wordlist file")
    bt.add_argument("--algo", default="auto", help="Algorithm (default: auto)")

    # demo
    sub.add_parser("demo", help="Run a demo with a built-in sample wordlist")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    print("=" * 60)
    print("  Hash Cracker Tool v1.0.0")
    print("  Educational Use Only")
    print("=" * 60)

    if args.command == "generate":
        generate_hash(args.text, args.algo)

    elif args.command == "identify":
        algo = identify_hash(args.hash)
        print(f"\n[*] Hash Identification")
        print(f"    Hash      : {args.hash}")
        print(f"    Detected  : {algo}")

    elif args.command == "dict":
        dictionary_attack(args.hash, args.wordlist, args.algo)

    elif args.command == "brute":
        brute_force_attack(args.hash, args.algo, args.charset,
                           args.min_len, args.max_len)

    elif args.command == "batch":
        batch_crack(args.hashes_file, args.wordlist, args.algo)

    elif args.command == "demo":
        print("\n[*] Running Demo Mode...")
        wl = create_sample_wordlist("sample_wordlist.txt")
        # Generate a test hash
        test_word = "password"
        test_hash = generate_hash(test_word, "md5")
        print(f"\n[*] Attempting to crack: {test_hash}")
        dictionary_attack(test_hash, wl, "md5")

        test_hash2 = generate_hash("guitar", "sha256")
        print(f"\n[*] Attempting to crack SHA-256: {test_hash2}")
        dictionary_attack(test_hash2, wl, "sha256")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
