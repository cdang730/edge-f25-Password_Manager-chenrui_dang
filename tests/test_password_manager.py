"""Tests for the implemented password manager functions.

These tests isolate storage by redirecting the data files to a tmp path.
"""

from pathlib import Path
import json
import hashlib
import pytest

import password_manager as pm


def use_tmp_storage(tmp_path: Path) -> None:
    """Point the password manager to temp JSON files so tests don't touch real data."""
    pm.USER_DATA_FILE = tmp_path / "user_data.json"
    pm.PASSWORDS_FILE = tmp_path / "passwords.json"


def test_register_user_writes_hashed_password(tmp_path: Path) -> None:
    use_tmp_storage(tmp_path)
    pm.register_user("alice", "secret")

    # user data file should be created and contain the hashed password
    assert pm.USER_DATA_FILE.exists()
    with open(pm.USER_DATA_FILE, "r") as f:
        users = json.load(f)

    assert "alice" in users
    expected = hashlib.sha256("secret".encode()).hexdigest()
    assert users["alice"] == expected


def test_add_and_get_passwords(tmp_path: Path) -> None:
    use_tmp_storage(tmp_path)
    # Add two distinct passwords
    pm.add_password("Alice","gmail", "alice", "a1")
    pm.add_password("Alice", "github", "alice", "a2")
    items = pm.get_passwords("Alice")

    # Should be a list of dicts
    assert isinstance(items, list)
    assert len(items) == 2
    # Check basic fields
    assert {"site", "username", "password"}.issubset(items[0].keys())