"""Simple password manager. Stores passwords for users and can search passwords. """
import json
import hashlib
from pathlib import Path
import os
import time
import shutil


# File paths
DATA_DIR = Path("data")
USER_DATA_FILE = DATA_DIR / "user_data.json"
PASSWORDS_FILE = DATA_DIR / "passwords.json"
BACKUP_FILE = DATA_DIR / "passwords.bak"
VERSION = "1.0"


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
    """Save data safely with temp rename + backup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)   # ✅ FIXED LINE
    temp_path = path.with_suffix(".tmp")
    # Backup
    if path.exists():
        shutil.copy2(path, BACKUP_FILE)
    
    with open(temp_path, "w") as f:
        json.dump(data, f, indent=4)

    temp_path.replace(path)


# User Authentication
# ---------------------


def register_user(username: str, master_password: str) -> None:
    """Register a new user with a master password."""
    users = load_json(USER_DATA_FILE, {})
    if username in users:
        print ("Username already exists.")
        return
    
    hashed_pw = hashlib.sha256(master_password.encode()).hexdigest()
    users[username] = hashed_pw
    save_json_safely(USER_DATA_FILE, users)

    clear_terminal()
    print(f"User -{username}- registered succssfully!")


def login(username: str, master_password: str) -> bool:
    """Check login credentials"""
    users = load_json(USER_DATA_FILE, {})
    hashed_pw = hashlib.sha256(master_password.encode()).hexdigest()

    if username in users and users[username] == hashed_pw:
        clear_terminal()
        print(f"Login successful! Welcome, {username}.\n")
        return True
    else:
        print(f"Invalid username or password")
        return False


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
        "id": str(int(time.time()*1000)),
        "site": site, 
        "username": username,
        "password": password,              # ✅ added missing password key
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
            print(f"Password: {entries[idx]['password']}")
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


def main():
    """Entry point for the password manager."""
    clear_terminal()
    print("🔐 Welcome to the Password Manager!")

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
                    print("8. Logout")

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
                        clear_terminal()
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
