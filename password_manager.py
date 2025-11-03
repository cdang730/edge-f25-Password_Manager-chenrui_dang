"""Simple password manager. Stores passwords for users and can search passwords. """
import json
import hashlib
from pathlib import Path
import os
import time
import shutil
import uuid
# Encryption imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64


# File paths
DATA_DIR = Path("data")
USER_DATA_FILE = DATA_DIR / "user_data.json"
PASSWORDS_FILE = DATA_DIR / "passwords.json"
BACKUP_FILE = DATA_DIR / "passwords.bak"
CHECKSUM_FILE = DATA_DIR / "passwords_checksum.txt"
VERSION = "1.0"

# Encryption Setup
# -------------------
SALT_FILE = DATA_DIR / "salt.bin"

def get_salt() -> bytes:
    """Get or create a persistent salt for key derivation."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SALT_FILE.exists():
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive encryption key from master password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


def encrypt_password(password: str, key: bytes) -> str:
    """Encrypt a password string using the derived key."""
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password: str, key: bytes) -> str:
    """Decrypt an encrypted password string using the derived key."""
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()



# Utility Functions
# -------------------
def clear_terminal() -> None:
    """Clear the terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def load_json(path:Path, default):
    if not path.exists():
        return default
    with open(path, "r") as f:
        return json.load(f)
    
def save_json_safely(path: Path, data):
    """Safely save data with backups, temp file, and verification."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")

    # Step 1: Make regular backup
    if path.exists():
        shutil.copy2(path, BACKUP_FILE)

        # Step 2: Make timestamped backup (optional, helpful for restore)
        timestamp = time.strftime("%Y-%m-%d-%H%M%S")
        timestamped_backup = DATA_DIR / f"{path.stem}-{timestamp}.bak"
        shutil.copy2(path, timestamped_backup)

    # Step 3: Write data to temp file
    with open(temp_path, "w") as f:
        json.dump(data, f, indent=4)

    # Step 4: Verify write was successful (basic validation)
    try:
        with open(temp_path, "r") as f:
            json.load(f)  # Ensure JSON is valid
    except json.JSONDecodeError:
        print("Save aborted: temp file invalid JSON.")
        return

    # Step 5: Atomically replace old file
    temp_path.replace(path)

    # Step 6: Update checksum after successful save
    update_checksum(path, CHECKSUM_FILE)


# Integrity and Versioning
# --------------------------

def compute_checksum(filepath: Path) -> str:
    """Compute SHA 256 checksum of a file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest()

def verify_integrity(filepath: Path, checksum_path: Path) -> bool:
    """Verify file integrity using checksum."""
    if not filepath.exists():
        print("No data file found. A new one will be created.")
        return False
    if not checksum_path.exists():
        print("No checksum file found. Integrity check skipped.")
        return False
    
    current_checksum = compute_checksum(filepath)
    with open(checksum_path, "r") as f:
        stored_checksum = f.read().strip()

    if current_checksum != stored_checksum:
        print("Integrity check FAILED! File may be corrupted or modified.")
        print("Password Manager will refuse to overwrite this file until you recover or inspect it.")
        return False
    
    print("Integrity check passed.")
    return True

def update_checksum(filepath: Path, checksum_path: Path):
    """Recompute and update checksum file after saving."""
    if filepath.exists():
        checksum = compute_checksum(filepath)
        with open(checksum_path, "w") as f:
            f.write(checksum)

# User Authentication
# ---------------------


def register_user(username: str, master_password: str) -> None:
    """Register a new user with a master password."""
    users = load_json(USER_DATA_FILE, {})
    if username in users:
        print ("Username already exists.")
        return
    
    while True:
        has_special: bool = False
        if len(master_password) == 0:
            print("Password Cannot be empty.")
            master_password = input("Please try again: ")
        elif len(master_password) < 8:
            print("Master password need to be at least 8 characters.")
            master_password = input("Please try again: ")
        else: 
            special_character: list[str] = ["!", "?", "@", "#", "$", "%"]
            i = 0
            has_special: bool = False
            while i < len(master_password):
                if master_password[i] in special_character:
                    has_special = True
                    break
                i += 1

            if not has_special:
                print("Must at least have one special character: !,?,@,#,$,%.")
                master_password = input("Please try again: ")
            else:
                hashed_pw = hashlib.sha256(master_password.encode()).hexdigest()
                users[username] = hashed_pw
                break
    
    save_json_safely(USER_DATA_FILE, users)
            
    clear_terminal()
    print(f"User -{username}- registered succssfully!")


def login(username: str, master_password: str) -> bool:
    """Check login credentials"""
    users = load_json(USER_DATA_FILE, {})
    hashed_pw = hashlib.sha256(master_password.encode()).hexdigest()

    if username in users and users[username] == hashed_pw:
        # Derive encryption key for this session
        salt = get_salt()
        global SESSION_KEY
        SESSION_KEY = derive_key(master_password, salt)
        clear_terminal()
        print(f"Login successful! Welcome, {username}.\n")
        return True
    else:
        print(f"Invalid username or password")
        return False

def lock_vault():
    """Temporarily lock the vault by clearing the session key."""
    global SESSION_KEY
    if SESSION_KEY is None:
        print("Vault is already locked.")
    else:
        SESSION_KEY = None
        print("🔒 Vault locked successfully.")


def unlock_vault():
    """Unlock the vault by asking for the master password again."""
    global SESSION_KEY
    if SESSION_KEY is not None:
        print("Vault is already unlocked.")
        return
    master_password = input("Enter your master password to unlock: ")
    salt = get_salt()
    SESSION_KEY = derive_key(master_password, salt)
    print("🔓 Vault unlocked successfully.")



# Password Management
# ----------------------


def get_passwords(owner:str) -> list[dict]:
    """Retrieve all stored passwords."""
    passwords = load_json(PASSWORDS_FILE, {"version":VERSION})
    return passwords.get(owner, [])

def save_passwords(owner:str, entries:list[dict]):
    passwords = load_json(PASSWORDS_FILE, {"version": VERSION})
    passwords["version"] = VERSION
    passwords[owner] = entries
    save_json_safely(PASSWORDS_FILE, passwords)
    update_checksum(PASSWORDS_FILE, CHECKSUM_FILE)

def mask_password(pw: str) -> str:
    return "*" * len(pw)

def add_password(owner: str, site: str, username: str, password: str, notes = "", tags = ""):
    """Store a password for a given site."""
    entries = get_passwords(owner)

    # Check duplicates
    duplicates = [e for e in entries if e["site"] == site and e["username"] == username]
    if duplicates:
        print(f"\nDuplicate found for ({site}, {username}).")
        choice = input("Do you want to (s)kip, (o)verwrite, or (k)eep both?").lower()
        if choice == "s":
            print("Skipped adding duplicate.")
            return
        elif choice == "o":
            entries = [e for e in entries if not (e["site"] == site and e["username"] == username)]
            print("Overwriting existing entry.")
        

    entry = {
        "id": str(uuid.uuid4())[:8],
        "site": site, 
        "username": username,
        "password": encrypt_password(password, SESSION_KEY),
        "notes": notes, 
        "tags": tags, 
        "last_updated": time.ctime()
    }

    entries.append(entry)
    save_passwords(owner, entries)

    clear_terminal()
    print(f"Password for -{site}- added successfully for username -{owner}!")


def list_password(owner: str):
    """List all stored passwords. + by different username"""
    entries = get_passwords(owner)
    clear_terminal()

    if not entries: 
        print("No passwords stored yet.")
        return
    print(f"Stored passwords for {owner}:")
    for i, e in enumerate(entries, 1):
        print(f"[{i}] {e['site']} | {e['username']} | {mask_password(e['password'])}")

    reveal = input("\nReveal a password? (y/n): ").lower()
    if reveal == "y":
        idx = int(input("Enter entry number to reveal: ")) - 1
        if 0 <= idx < len(entries):
            try:
                decrypted = decrypt_password(entries[idx]['password'], SESSION_KEY)
                print(f"Password: {decrypted}")
            except Exception:
                print("Error decrypting password. Possibly wrong key or corrupted data.")
        else:
            print("invalid selection.")


def search_passwords(owner: str, query: str):
    """Search passwords by site name."""
    entries = get_passwords(owner)
    results = [e for e in entries if query.lower() in e["site"].lower()]

    clear_terminal()
    if not results:
        print(f"No matches for '{query}'. ")
        return
    
    print(f"Search results for '{query}':")
    for e in results: 
        print(f"{e['site']} | {e['username']} | {mask_password(e['password'])}")


def edit_password(owner:str):
    entries = get_passwords(owner)
    list_password(owner)

    if not entries:
        return
    
    idx = int(input("\nEnter entry number to edit: ")) - 1
    if not(0 <= idx < len(entries)):
        print("Invalid selection.")
        return
    e = entries[idx]
    print(f"Editing entry for {e['site']} ({e['username']})")
    e["site"] = input(f"New site (blank to keep '{e['site']}'): ") or e["site"]
    e["username"] = input(f"New username (blank to keep '{e['username']}'): ") or e["username"]
    e["password"] = input(f"New password (blank to keep current): ") or e["password"]
    e["notes"] = input(f"Notes (blank to keep current): ") or e.get("notes", "")
    e["tags"] = input(f"Tags (blank to keep current): ") or e.get("tags", "")
    e["last_updated"] = time.ctime()

    entries[idx] = e
    save_passwords(owner, entries)
    print("Entry updated successfully.")


def delete_password(owner: str):
    entries = get_passwords(owner)
    list_password(owner)

    if not entries:
        return
    idx = int(input("\nEnter entry number to delete: ")) - 1
    if not (0 <= idx < len(entries)):
        print("Invalid selection.")
        return

    confirm = input(f"⚠️ Are you sure you want to delete {entries[idx]['site']} ({entries[idx]['username']})? (y/n): ").lower()
    if confirm != "y":
        print("Deletion cancelled.")
        return

    removed = entries.pop(idx)
    save_passwords(owner, entries)
    print(f"Deleted password for {removed['site']} ({removed['username']}).")


# Import/Export
# ---------------

def export_passwords(owner:str):
    entries = get_passwords(owner)
    export_path = DATA_DIR / f"{owner}_export.json" 
    with open(export_path, "w") as f:
        json.dump(entries, f, indent = 4)

    print(f"Exported to {export_path}") 

def import_passwords(owner:str):
    path = input("Enter import JSON filename: ").strip()
    if not Path(path).exists():
        print("File not found.")
        return
    with open(path,"r") as f:
        imported = json.load(f)

    if not isinstance(imported, list):
        print("Invalid format.")
        return
    
    existing = get_passwords(owner)
    for entry in imported:
        site = entry.get("site")
        user = entry.get("username")
        dupes = [e for e in existing if e["site"] == site and e["username"] == user]
        if dupes:
            print(f"Collision: ({site}, {user}) already exists.")
            choice = input("Do you want to (s)kip, (o)verwrite, or (k)eep both? ").lower()
            if choice == "s":
                continue
            elif choice == "o":
                existing = [e for e in existing if not (e["site"] == site and e["username"] == user)]

        existing.append(entry)

    save_passwords(owner, existing)
    print("📥 Import completed.")

# Main CLI
# ----------
def show_help():
    """Display available commands and descriptions."""
    clear_terminal()
    print("📘 Password Manager Help\n")
    print("1. Add new password - Save a new encrypted password entry.")
    print("2. List passwords - Show all your stored accounts (masked by default).")
    print("3. Search by site - Quickly find passwords by site name.")
    print("4. Edit password - Update an existing entry.")
    print("5. Delete password - Remove an entry (you’ll be asked to confirm).")
    print("6. Export passwords - Save all entries to a JSON file.")
    print("7. Import passwords - Load entries from another JSON file.")
    print("8. Lock vault - Temporarily disable password access.")
    print("9. Unlock vault - Re-enable access with your master password.")
    print("10. Logout - Exit your account.")
    print("11. Help - Show this guide.")
    print("\nTip: Keep your vault locked if stepping away. All passwords are encrypted.")


def main():
    """Entry point for the password manager."""
    clear_terminal()
    print("🔐 Welcome to the Password Manager!")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ok = verify_integrity(PASSWORDS_FILE, CHECKSUM_FILE)
    # check version if file exists
    if PASSWORDS_FILE.exists():
        data = load_json(PASSWORDS_FILE, {})
        file_version = data.get("version", "0.0")
        if file_version != VERSION:
            print("File version {file_version} does not match program version: {VERSION}. ")
            print("Updating file version info.")
            data["version"] = VERSION
            save_json_safely(PASSWORDS_FILE, data)
            update_checksum(PASSWORDS_FILE, CHECKSUM_FILE)

    while True:
        action = input("Do you want to (r)egister, (l)ogin, or (q)uit? \n")

        if action == "r":
            u = input("Enter new username: ")
            p = input("Enter master password: ")
            register_user(u, p)
        elif action == "l":
            u = input("Enter username: ")
            p = input("Enter master password: ")

            if login(u, p) == True:
                # Enter menu loop for add or get password
                while True:
                    print("\nMain Menu:")
                    print("1. Add new password")
                    print("2. List passwords")
                    print("3. Search by site")
                    print("4. Edit password")
                    print("5. Delete password")
                    print("6. Export passwords")
                    print("7. Import passwords")
                    print("8. Lock vault")
                    print("9. Unlock vault")
                    print("10. Help")
                    print("11. Logout")

                    choice = input("Choose an option by select the number: ").strip()

                    if choice == "1":
                        site = input("Site name: ")
                        user = input("Site username: ")
                        pw = input("Site password: ")
                        notes = input("Notes (optional): ")
                        tags = input("Tags (optional): ")
                        add_password(u, site, user, pw, notes, tags)

                    elif choice == "2":
                        list_password(u)

                    elif choice == "3":
                        q = input("Search term: ")
                        search_passwords(u, q)

                    elif choice == "4":
                        edit_password(u)

                    elif choice == "5":
                        delete_password(u)
                    
                    elif choice == "6":
                        export_passwords(u)

                    elif choice == "7":
                        import_passwords(u)

                    elif choice == "8":
                        lock_vault()
                    
                    elif choice == "9":
                        unlock_vault()
                    
                    elif choice == "10":
                        show_help()

                    elif choice == "11":
                        clear_terminal()
                        global SESSION_KEY
                        SESSION_KEY = None
                        print("Logging out...\nBack to homepage ... \n")
                        break
                    else:
                        print("Invalid choice, try again.")
        
        elif action == "q":
            print("Thanks for using Password Manager, Goodbye!")
            break

        else:
            print("Invalid option. Please type r, l, or q.")


if __name__ == "__main__":
    main()
