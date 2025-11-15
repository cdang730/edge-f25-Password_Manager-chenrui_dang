# Password Manager
A secure, encrypted command-line password manager built with Python.
It supports multi-user login, encrypted password storage, backups, integrity checks, imports/exports, vault locking, and more.

## Feature
- User registration and login
    - Input validation on master password
    - Use SHA-256 hashed credentials
- Input validation on master password
- Encrypt every password stored
    - AES-128 encryption via cryptography.Fernet  
    - Persistend salt
    - Unique encryption key derived from the master password
- Add, list, search, edit, reveal, and delete passwords
- Lock/Unlock Vault for safety
- Import/export password data as JSON
- Automatic backup on save
    - Regular backup (passwords.bak)  
    - Timestamped backup 
    - Check for data corruption
- Clean terminal interface

## Troubleshooting
- Invalid checksum
    Data file was modified, corrupted, or not written atomically. Program will refuse to load it. Restor from passwords.bak
- Salt missing or corrupted
    Delete salt.bin and re-register a new user.
- Fernet key invalid
    Wrong master password during unlocing.

## Golden Path
Start the app:
```python -m password_manager```
Register a user:
    Type r in the terminal and follow the steps for username and master password.
    Type l in the terminal to login.
Main menu:
    Type the corresponding number.
    1. Add new password
        Enter site, username, password, storing in json.
    2. List password
        List existing passwords
    3. Search by site
    4. Edit password
    5. Delete password
    6. Export passwords
    7. Import passwords
    8. Lock vault
    9. Unlock vault
    10. Help
