# National Security Language Encryption System (RBAC Edition)

Role-based substitution encryption and intelligence analysis desktop application built with Python and PySide6.

## Department Roles & Permissions
1. **Admin (`admin` / `admin123`)**
   - Exclusive authority to edit, add, remove, or reset the encryption language dictionary (`language_mapping.json`).
   - Exclusive authority to create, revoke, or reset passwords for **Subadmin** and **Analyst** accounts (`users.json`).
   - Full access to encrypt/decrypt messages, run intelligence analysis, and inspect the security audit trail (`security_audit.log`).
2. **Subadmin — Officials (`subadmin1` / `sub123`)**
   - Authorized to encrypt and decrypt official communications using the active cipher language.
   - Cannot modify the encryption language or create/manage user accounts.
3. **Analyst (`analyst1` / `analyst123`)**
   - Dedicated **Intelligence Analysis** workspace for symbol frequency distribution, cipher coverage metrics, plaintext vs. ciphertext detection, and unmapped character inspection.
   - Cannot edit the encryption language, manage accounts, or alter operational cipher settings.

## Run on Windows
```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```
