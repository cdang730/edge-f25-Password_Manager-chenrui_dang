## Security Features
1. Password Encryption
- Stored passwords are encrypted with Fernet (AES-128 + HMAC).
- Master password derives a key:
    - PbKDF2-HMAC-SHA256
    - 100,000 iterations
    - 16 byte salt
2. Integrity Protection
- SHA-256 checksum
3. Backups
- Automatic backup
- Timestamped backup
- Precents irrecersible data loss
4. User Authentication
- Master passwords hashed with SHA-256
- Password must conatin at least one special character

## Known Limitations
- No two-factor authentication
- No secure deletion (file-level)
- If user forget master password, data is unrecoverable
- Uses local file storage only