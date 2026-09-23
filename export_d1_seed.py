import hashlib
import secrets
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DB = ROOT / "data" / "mis_students.sqlite3"
CREDS = ROOT / "data" / "initial_admin_credentials.txt"
OUT = ROOT / "cf-pages" / "seed.sql"


def q(value):
    if value is None:
        return "NULL"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def admin_hash():
    username = "admin"
    password = ""
    if CREDS.exists():
        for line in CREDS.read_text(encoding="utf-8").splitlines():
            if line.startswith("Username:"):
                username = line.split(":", 1)[1].strip() or username
            if line.startswith("Password:"):
                password = line.split(":", 1)[1].strip()
    if not password:
        password = secrets.token_urlsafe(24) + "!Aa7"
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return username, f"sha256${salt}${digest}"


def main():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    lines = ["DELETE FROM admins;"]
    username, password_hash = admin_hash()
    lines.append(
        f"INSERT INTO admins(id,username,password_hash,role) VALUES(1,{q(username)},{q(password_hash)},'admin');"
    )
    tables = ["subjects", "lectures", "explanations", "announcements", "exams", "requests", "visits"]
    for table in tables:
        lines.append(f"DELETE FROM {table};")
        rows = conn.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
        for row in rows:
            data = dict(row)
            if table in ("lectures", "explanations"):
                data.setdefault("file_mime", "")
                data["file_data"] = ""
            cols = ",".join(data)
            vals = ",".join(q(v) for v in data.values())
            lines.append(f"INSERT INTO {table}({cols}) VALUES({vals});")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
