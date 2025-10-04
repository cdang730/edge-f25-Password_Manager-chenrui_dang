"""Simple password manager (stub).

This module provides placeholder functions for a command‑line password
manager.  Eventually it will allow users to register with a master
password, store encrypted passwords for various sites and retrieve them.
For now, it contains stubs that raise `NotImplementedError` and prints
a greeting when executed.
"""
import json
import hashlib
from pathlib import Path

# File paths
USER_DATA_FILE = Path("data/user_data.json")
PASSWORDS_FILE = Path("data/passwords.json")

def register_user(username: str, master_password: str) -> None:
    """Register a new user with a master password.

    You will hash and store the master password in a
    JSON file for authentication.  This stub does nothing.

    Args:
        username: The username for the account.
        master_password: The master password to use.
    """
    hashed_pw = hashlib.sha256(master_password.encode()).hexdigest()
    # load existing, else empty dict
    if USER_DATA_FILE.exists():
        with open(USER_DATA_FILE, "r") as f:
            users = json.load(f)
    else:
        users = {}

    # save or update user
    users[username] = hashed_pw

    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f, indent = 4)


def add_password(site: str, username: str, password: str) -> None:
    """Store a password for a given site.

    You will encrypt the password and save it to a JSON file,
    associating it with the site and username.  This stub does nothing.

    Args:
        site: The website or service name.
        username: The account username for the site.
        password: The password to store.
    """
    # Store a password for a given site.
    entry = {"site": site, "username": username, "password": password}

    # Load existing entries if file exists, else empty list
    if PASSWORDS_FILE.exists():
        with open(PASSWORDS_FILE, "r") as f:
            passwords = json.load(f)
    else:
        passwords = []

    passwords.append(entry)

    with open(PASSWORDS_FILE, "w") as f:
        json.dump(passwords, f, indent=4)


def get_passwords() -> list[dict]:
    """Retrieve all stored passwords.

    This will read from an encrypted JSON file and return a list
    of dictionaries containing site, username and password.  For now
    it raises `NotImplementedError`.

    Returns:
        A list of stored passwords.
    """
    raise NotImplementedError("get_passwords is not yet implemented")


def main() -> None:
    """Entry point for the password manager.

    When run directly, this prints a greeting.  You will replace this
    with registration, login and menu functionality in future ships.
    """
    print("Welcome to the Password Manager!")


if __name__ == "__main__":
    main()