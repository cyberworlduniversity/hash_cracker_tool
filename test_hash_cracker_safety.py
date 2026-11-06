import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import hash_cracker


class HashCrackerInputSafetyTests(unittest.TestCase):
    def test_identify_rejects_non_hex_digest(self):
        self.assertIn("invalid hexadecimal", hash_cracker.identify_hash("g" * 32).lower())

    def test_detect_algorithm_rejects_invalid_or_unknown_digest(self):
        with self.assertRaises(ValueError):
            hash_cracker.detect_algorithm("not-a-hash")
        with self.assertRaises(ValueError):
            hash_cracker.detect_algorithm("a" * 33)

    def test_compute_hash_rejects_unsupported_algorithm(self):
        with self.assertRaises(ValueError):
            hash_cracker.compute_hash("sample", "not-an-algorithm")

    def test_dictionary_attack_rejects_mismatched_hash(self):
        result = hash_cracker.dictionary_attack("z" * 32, "missing.txt", "md5")
        self.assertFalse(result["success"])
        self.assertIn("hexadecimal", result["error"])

    def test_brute_force_rejects_excessive_length_and_invalid_charset(self):
        result = hash_cracker.brute_force_attack("5f4dcc3b5aa765d61d8327deb882cf99",
                                                 charset="lowercase", min_length=1, max_length=7)
        self.assertFalse(result["success"])
        self.assertIn("1 <=", result["error"])
        invalid = hash_cracker.brute_force_attack("5f4dcc3b5aa765d61d8327deb882cf99",
                                                  charset="unknown", min_length=1, max_length=1)
        self.assertIn("character set", invalid["error"])

    def test_brute_force_candidate_count_is_bounded(self):
        result = hash_cracker.brute_force_attack("5f4dcc3b5aa765d61d8327deb882cf99",
                                                 charset="all", min_length=1, max_length=4)
        self.assertFalse(result["success"])
        self.assertIn("safety limit", result["error"])

    def test_wordlist_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.txt"
            with path.open("wb") as handle:
                handle.truncate(hash_cracker.MAX_WORDLIST_BYTES + 1)
            result = hash_cracker.dictionary_attack("5f4dcc3b5aa765d61d8327deb882cf99",
                                                    str(path), "md5")
            self.assertIn("100 MiB", result["error"])


if __name__ == "__main__":
    unittest.main()
