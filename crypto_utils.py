"""
crypto_utils.py

Secure password hashing and verification using Bcrypt.

Bcrypt automatically generates and embeds a unique, cryptographically
random salt in every hash it produces (visible in the hash's second
field, e.g. "$2b$12$<22-char-salt><31-char-hash>"), so calling
hash_password() twice with the same plaintext input yields two
different stored hashes.
"""

import bcrypt

# Work factor (log2 of the number of rounds). 12 is a reasonable default
# for 2026-era hardware; raise it as hardware gets faster to keep the
# per-guess cost roughly constant.
BCRYPT_ROUNDS = 12


def hash_password(plain_text: str) -> str:
    """
    Generate a unique salt and return the salted Bcrypt hash for
    plain_text, encoded as a UTF-8 string suitable for storing in a
    database TEXT/VARCHAR column.
    """
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(plain_text.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_text: str, stored_hash: str) -> bool:
    """
    Verify plain_text against a previously stored Bcrypt hash.
    Returns True if it matches, False otherwise. Never raises on a
    non-matching password; only malformed stored_hash values raise.
    """
    return bcrypt.checkpw(plain_text.encode("utf-8"), stored_hash.encode("utf-8"))


if __name__ == "__main__":
    # Demonstration: same input, two calls, two different hashes.
    pw = "CorrectHorseBatteryStaple!42"
    h1 = hash_password(pw)
    h2 = hash_password(pw)

    print("Hash #1:", h1)
    print("Hash #2:", h2)
    print("Hashes are different:", h1 != h2)
    print("verify_password(pw, h1):", verify_password(pw, h1))
    print("verify_password(pw, h2):", verify_password(pw, h2))
    print("verify_password('wrong-password', h1):", verify_password("wrong-password", h1))
