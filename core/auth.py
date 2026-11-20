import hashlib
import json
import secrets
from pathlib import Path

USERS_FILE = Path(__file__).resolve().parent.parent / "users.json"

ROLE_ADMIN = "Admin"
ROLE_SUBADMIN = "Subadmin"
ROLE_ANALYST = "Analyst"
VALID_ROLES = (ROLE_ADMIN, ROLE_SUBADMIN, ROLE_ANALYST)


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        120_000,
    ).hex()


def create_user_record(username: str, password: str, role: str, full_name: str = "") -> dict:
    salt = secrets.token_hex(16)
    return {
        "username": username.strip(),
        "full_name": full_name.strip() or username.strip(),
        "role": role,
        "salt": salt,
        "password_hash": _hash_password(password, salt),
    }


def _default_users() -> dict:
    return {
        "admin": create_user_record("admin", "admin123", ROLE_ADMIN, "Chief Security Administrator"),
        "subadmin1": create_user_record("subadmin1", "sub123", ROLE_SUBADMIN, "Field Operations Official"),
        "analyst1": create_user_record("analyst1", "analyst123", ROLE_ANALYST, "Intelligence Analyst"),
    }


def load_users() -> dict:
    if not USERS_FILE.exists():
        users = _default_users()
        save_users(users)
        return users
    try:
        data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not data:
            users = _default_users()
            save_users(users)
            return users
        return data
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        users = _default_users()
        save_users(users)
        return users


def save_users(users: dict) -> None:
    USERS_FILE.write_text(
        json.dumps(users, ensure_ascii=False, indent=4),
        encoding="utf-8",
    )


def authenticate(username: str, password: str):
    users = load_users()
    record = users.get(username.strip())
    if not record:
        return None
    expected = record.get("password_hash", "")
    salt = record.get("salt", "")
    if not expected or not salt:
        return None
    candidate = _hash_password(password, salt)
    if secrets.compare_digest(candidate, expected):
        return record
    return None


def add_user(actor: dict, username: str, password: str, role: str, full_name: str = "") -> tuple[bool, str]:
    if not actor or actor.get("role") != ROLE_ADMIN:
        return False, "Access Denied: Only the Admin can create or manage accounts."

    clean_user = username.strip()
    if not clean_user:
        return False, "Username cannot be empty."
    if len(clean_user) < 3:
        return False, "Username must be at least 3 characters long."
    if len(password) < 4:
        return False, "Password must be at least 4 characters long."
    if role not in (ROLE_SUBADMIN, ROLE_ANALYST):
        return False, "Admin can only create Subadmin or Analyst accounts."

    users = load_users()
    if clean_user in users:
        return False, f'Username "{clean_user}" already exists.'

    users[clean_user] = create_user_record(clean_user, password, role, full_name)
    save_users(users)
    return True, f'{role} account "{clean_user}" created successfully.'


def remove_user(actor: dict, target_username: str) -> tuple[bool, str]:
    if not actor or actor.get("role") != ROLE_ADMIN:
        return False, "Access Denied: Only the Admin can remove accounts."

    clean_user = target_username.strip()
    users = load_users()
    target = users.get(clean_user)
    if not target:
        return False, "Selected user does not exist."
    if target.get("role") == ROLE_ADMIN:
        return False, "The primary Admin account cannot be deleted."

    del users[clean_user]
    save_users(users)
    return True, f'Account "{clean_user}" has been removed.'


def reset_user_password(actor: dict, target_username: str, new_password: str) -> tuple[bool, str]:
    if not actor or actor.get("role") != ROLE_ADMIN:
        return False, "Access Denied: Only the Admin can reset passwords."
    if len(new_password) < 4:
        return False, "New password must be at least 4 characters long."

    users = load_users()
    target = users.get(target_username.strip())
    if not target:
        return False, "User not found."

    salt = secrets.token_hex(16)
    target["salt"] = salt
    target["password_hash"] = _hash_password(new_password, salt)
    save_users(users)
    return True, f'Password updated for "{target_username}".'
