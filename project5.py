#!/usr/bin/env python3
"""
Password Manager (Local)
Store encrypted passwords in a local file using cryptography.
Supports add, retrieve, delete, and list commands.
Master password protects everything.
"""

import json
import os
import getpass
import secrets
import hashlib
from typing import Dict, List, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

PASSWORD_FILE = "passwords.enc"
SALT_FILE = "salt.bin"

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive encryption key from master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def get_or_create_salt() -> bytes:
    """Get existing salt or create new one."""
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as f:
            return f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
        return salt

def encrypt_data(data: str, master_password: str) -> bytes:
    """Encrypt data with master password."""
    salt = get_or_create_salt()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data: bytes, master_password: str) -> Optional[str]:
    """Decrypt data with master password."""
    salt = get_or_create_salt()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data.decode()
    except Exception:
        return None

def load_passwords(master_password: str) -> Dict:
    """Load passwords from encrypted file."""
    if not os.path.exists(PASSWORD_FILE):
        return {}
    
    try:
        with open(PASSWORD_FILE, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_data(encrypted_data, master_password)
        if decrypted_data is None:
            return None  # Wrong password
        
        return json.loads(decrypted_data)
    except Exception:
        return None

def save_passwords(passwords: Dict, master_password: str) -> bool:
    """Save passwords to encrypted file."""
    try:
        data = json.dumps(passwords, indent=2)
        encrypted_data = encrypt_data(data, master_password)
        
        with open(PASSWORD_FILE, 'wb') as f:
            f.write(encrypted_data)
        
        return True
    except Exception:
        return False

def verify_master_password(master_password: str) -> bool:
    """Verify if master password is correct."""
    if not os.path.exists(PASSWORD_FILE):
        return True  # No file yet, any password is fine
    
    passwords = load_passwords(master_password)
    return passwords is not None

def generate_password(length: int = 12, include_symbols: bool = True) -> str:
    """Generate a secure random password."""
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numbers = "0123456789"
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    charset = letters + numbers
    if include_symbols:
        charset += symbols
    
    password = ''.join(secrets.choice(charset) for _ in range(length))
    
    # Ensure at least one character from each category
    if include_symbols:
        if not any(c in letters for c in password):
            password = secrets.choice(letters) + password[1:]
        if not any(c in numbers for c in password):
            password = password[0] + secrets.choice(numbers) + password[2:]
        if not any(c in symbols for c in password):
            password = password[:2] + secrets.choice(symbols) + password[3:]
    else:
        if not any(c in letters for c in password):
            password = secrets.choice(letters) + password[1:]
        if not any(c in numbers for c in password):
            password = password[0] + secrets.choice(numbers) + password[2:]
    
    return password

def add_password(master_password: str) -> None:
    """Add a new password entry."""
    passwords = load_passwords(master_password)
    
    if passwords is None:
        print("Error: Invalid master password!")
        return
    
    print("\nAdd New Password")
    print("-" * 20)
    
    service = input("Service/Website name: ").strip()
    if not service:
        print("Service name is required!")
        return
    
    username = input("Username/Email: ").strip()
    if not username:
        print("Username is required!")
        return
    
    # Ask if user wants to generate password
    generate = input("Generate password? (Y/n): ").strip().lower()
    
    if generate != 'n':
        try:
            length = int(input("Password length (default 12): ") or "12")
            length = max(8, min(50, length))
            
            include_symbols = input("Include symbols? (Y/n): ").strip().lower() != 'n'
            
            password = generate_password(length, include_symbols)
            print(f"Generated password: {password}")
        except ValueError:
            print("Invalid length! Using default.")
            password = generate_password()
    else:
        password = getpass.getpass("Password: ")
        if not password:
            print("Password is required!")
            return
    
    notes = input("Notes (optional): ").strip()
    
    # Create entry
    entry = {
        "username": username,
        "password": password,
        "notes": notes,
        "created": __import__('datetime').datetime.now().isoformat()
    }
    
    passwords[service] = entry
    
    if save_passwords(passwords, master_password):
        print(f"Password saved for {service}")
    else:
        print("Error saving password!")

def get_password(master_password: str) -> None:
    """Retrieve a password."""
    passwords = load_passwords(master_password)
    
    if passwords is None:
        print("Error: Invalid master password!")
        return
    
    if not passwords:
        print("No passwords stored!")
        return
    
    print("\nAvailable services:")
    services = list(passwords.keys())
    for i, service in enumerate(services, 1):
        print(f"{i}. {service}")
    
    try:
        choice = int(input("Select service number: ")) - 1
        if 0 <= choice < len(services):
            service = services[choice]
            entry = passwords[service]
            
            print(f"\nService: {service}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            if entry['notes']:
                print(f"Notes: {entry['notes']}")
            print(f"Created: {entry['created'][:10]}")
        else:
            print("Invalid selection!")
    except ValueError:
        print("Invalid input!")

def list_passwords(master_password: str) -> None:
    """List all stored services."""
    passwords = load_passwords(master_password)
    
    if passwords is None:
        print("Error: Invalid master password!")
        return
    
    if not passwords:
        print("No passwords stored!")
        return
    
    print("\nStored Passwords")
    print("-" * 30)
    
    for service, entry in passwords.items():
        created = entry['created'][:10]
        print(f"Service: {service}")
        print(f"Username: {entry['username']}")
        print(f"Created: {created}")
        print("-" * 30)

def delete_password(master_password: str) -> None:
    """Delete a password entry."""
    passwords = load_passwords(master_password)
    
    if passwords is None:
        print("Error: Invalid master password!")
        return
    
    if not passwords:
        print("No passwords stored!")
        return
    
    print("\nDelete Password")
    print("-" * 15)
    
    services = list(passwords.keys())
    for i, service in enumerate(services, 1):
        print(f"{i}. {service}")
    
    try:
        choice = int(input("Select service number to delete: ")) - 1
        if 0 <= choice < len(services):
            service = services[choice]
            
            confirm = input(f"Delete password for '{service}'? (yes/no): ").strip().lower()
            if confirm == 'yes':
                del passwords[service]
                if save_passwords(passwords, master_password):
                    print(f"Deleted password for {service}")
                else:
                    print("Error deleting password!")
            else:
                print("Deletion cancelled.")
        else:
            print("Invalid selection!")
    except ValueError:
        print("Invalid input!")

def change_master_password() -> None:
    """Change the master password."""
    print("\nChange Master Password")
    print("-" * 25)
    
    current_password = getpass.getpass("Enter current master password: ")
    
    if not verify_master_password(current_password):
        print("Invalid current password!")
        return
    
    new_password = getpass.getpass("Enter new master password: ")
    confirm_password = getpass.getpass("Confirm new master password: ")
    
    if new_password != confirm_password:
        print("Passwords don't match!")
        return
    
    if len(new_password) < 8:
        print("Password must be at least 8 characters!")
        return
    
    # Load with old password and save with new password
    passwords = load_passwords(current_password)
    
    if passwords is None:
        print("Error with current password!")
        return
    
    # Save with new password
    if save_passwords(passwords, new_password):
        print("Master password changed successfully!")
    else:
        print("Error changing master password!")

def main_menu() -> None:
    """Main password manager menu."""
    print("\n" + "=" * 40)
    print("PASSWORD MANAGER")
    print("=" * 40)
    
    # Get master password
    master_password = getpass.getpass("Enter master password: ")
    
    if not verify_master_password(master_password):
        print("Invalid master password!")
        return
    
    while True:
        print("\n" + "-" * 40)
        print("1. Add Password")
        print("2. Get Password")
        print("3. List Services")
        print("4. Delete Password")
        print("5. Change Master Password")
        print("6. Exit")
        
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == '1':
            add_password(master_password)
        elif choice == '2':
            get_password(master_password)
        elif choice == '3':
            list_passwords(master_password)
        elif choice == '4':
            delete_password(master_password)
        elif choice == '5':
            change_master_password()
            break  # Exit to re-login with new password
        elif choice == '6':
            print("Goodbye!")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nGoodbye!")
