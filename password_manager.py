"""Simple password manager. Stores passwords for users and can search passwords. """
import json
import hashlib
from pathlib import Path
import os


# File paths
USER_DATA_FILE = Path("data/user_data.json")
PASSWORDS_FILE = Path("data/passwords.json")

def register_user(username: str, master_password: str) -> None:
    """Register a new user with a master password."""
    hashed_pw = hashlib.sha256(master_password.encode()).hexdigest()
    # load existing, else empty dict
    if USER_DATA_FILE.exists():
        with open(USER_DATA_FILE, "r") as f:
            users = json.load(f)
    else:
        users = {}

    # save or update user
    if username in users:
        print("Username exists")
        return

    users[username] = hashed_pw

    USER_DATA_FILE.parent.mkdir(exist_ok=True)
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f, indent = 4)

    clear_terminal()
    print(f"User -{username}- registered succssfully!")


def login(username: str, master_password: str) -> bool:
    """Check login credentials"""
    if not USER_DATA_FILE.exists():
        clear_terminal()
        print("No users found. Please register.")
        return False
    
    with open(USER_DATA_FILE, "r") as f:
        users = json.load(f)

    hashed_pw = hashlib.sha256(master_password.encode()).hexdigest()

    if username in users and users[username] == hashed_pw:
        clear_terminal()
        print("Login successful!")    
        return True
    else:
        clear_terminal()
        print("Invalid user name or password. Please try again.")
        return False


def add_password(owner: str, site: str, username: str, password: str) -> None:
    """Store a password for a given site."""
    # Store a password for a given site.
    entry = {"site": site, "username": username, "password": password}

    # Load existing entries if file exists, else empty list
    if PASSWORDS_FILE.exists():
        with open(PASSWORDS_FILE, "r") as f:
            passwords = json.load(f)
    else:
        passwords = {}

    # create section by user name
    if owner not in passwords:
        passwords[owner] = []

    passwords[owner].append(entry)

    PASSWORDS_FILE.parent.mkdir(exist_ok=True)
    with open(PASSWORDS_FILE, "w") as f:
        json.dump(passwords, f, indent=4)

    clear_terminal()
    print(f"Password for -{site}- added successfully for username -{owner}!")


def get_passwords(owner:str) -> list[dict]:
    """Retrieve all stored passwords."""
    if not PASSWORDS_FILE.exists():
        return []
    with open(PASSWORDS_FILE, "r") as f:
        passwords = json.load(f)
    return passwords.get(owner, [])

def list_password(owner: str) -> None:
    """List all stored passwords. + by different username"""
    passwords = get_passwords(owner)
    if not passwords:
        clear_terminal()
        print("No passwords stored yet.")
        return
    
    for entry in passwords:
        clear_terminal()
        print(f"Site: {entry['site']} | Username: {entry['username']} | Password: {entry['password']}")


def search_passwords(owner: str, site_name: str) -> None:
    """Search passwords by site name."""
    passwords = get_passwords(owner)
    results = [p for p in passwords if site_name.lower() in p["site"].lower()]

    if results:
        for entry in results:
            clear_terminal()
            print(f"Site: {entry['site']} | Username: {entry['username']} | Password: {entry['password']}")
    else:
        clear_terminal()
        print(f"No passwords found for -{site_name}-.")

def clear_terminal() -> None:
    """Clear the terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def main() -> None:
    """Entry point for the password manager."""
    print("🔐 Welcome to the Password Manager!")

    while True:
        action = input("Do you want to (r)egister, (l)ogin, or (q)uit? \n")

        if action == "r":
            username = input("Enter new username: ")
            password = input("Enter master password: ")
            register_user(username, password)
        elif action == "l":
            username = input("Enter username: ")
            password = input("Enter master password: ")

            if login(username, password) == True:
                # Enter menu loop for add or get password
                while True:
                    print("\nMain Menu:")
                    print("1. Add new password")
                    print("2. List passwords")
                    print("3. Search by site")
                    print("4. Logout")
                    choice = input("Choose an option by select the number: ")

                    if choice == "1":
                        site = input("Site name: ")
                        user = input("Site username: ")
                        pw = input("Site password: ")
                        add_password(username, site, user, pw)

                    elif choice == "2":
                        list_password(username)

                    elif choice == "3":
                        search = input("Enter site name to search: ")
                        search_passwords(username, search)

                    elif choice == "4":
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