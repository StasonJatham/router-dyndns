from __future__ import annotations

import secrets
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .ddns_models import UpdateResult
from .ddns_security import hash_lookup_token, hash_secret, verify_secret


class DdnsStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def upsert(
        self,
        hostname: str,
        ipv4: str | None,
        ipv6: str | None,
        update_ipv4: bool = True,
        update_ipv6: bool = True,
    ) -> UpdateResult:
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            existing = conn.execute("SELECT ipv4, ipv6 FROM records WHERE hostname = ?", (hostname,)).fetchone()
            current_ipv4 = existing["ipv4"] if existing else None
            current_ipv6 = existing["ipv6"] if existing else None
            effective_ipv4 = ipv4 if update_ipv4 else current_ipv4
            effective_ipv6 = ipv6 if update_ipv6 else current_ipv6
            changed = existing is None or current_ipv4 != effective_ipv4 or current_ipv6 != effective_ipv6
            conn.execute(
                """
                INSERT INTO records(hostname, ipv4, ipv6, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(hostname) DO UPDATE SET
                  ipv4=excluded.ipv4,
                  ipv6=excluded.ipv6,
                  updated_at=excluded.updated_at
                """,
                (hostname, effective_ipv4, effective_ipv6, now),
            )
        return UpdateResult(
            hostname=hostname,
            ipv4=effective_ipv4,
            ipv6=effective_ipv6,
            changed=changed,
            update_ipv4=update_ipv4,
            update_ipv6=update_ipv6,
        )

    def preview_update(
        self,
        hostname: str,
        ipv4: str | None,
        ipv6: str | None,
        update_ipv4: bool = True,
        update_ipv6: bool = True,
    ) -> UpdateResult:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            existing = conn.execute("SELECT ipv4, ipv6 FROM records WHERE hostname = ?", (hostname,)).fetchone()
        current_ipv4 = existing["ipv4"] if existing else None
        current_ipv6 = existing["ipv6"] if existing else None
        effective_ipv4 = ipv4 if update_ipv4 else current_ipv4
        effective_ipv6 = ipv6 if update_ipv6 else current_ipv6
        changed = existing is None or current_ipv4 != effective_ipv4 or current_ipv6 != effective_ipv6
        return UpdateResult(
            hostname=hostname,
            ipv4=effective_ipv4,
            ipv6=effective_ipv6,
            changed=changed,
            update_ipv4=update_ipv4,
            update_ipv6=update_ipv6,
        )

    def create_account(
        self,
        hostname: str,
        username: str | None = None,
        owner_user_id: int | None = None,
    ) -> dict[str, str]:
        now = datetime.now(UTC).isoformat()
        token = secrets.token_urlsafe(24)
        update_slug = secrets.token_urlsafe(32)
        management_slug = secrets.token_urlsafe(32)
        username = username or _default_username(hostname)
        token_hash = hash_secret(token)
        management_hash = hash_lookup_token(management_slug)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO accounts(hostname, username, token_hash, update_slug, management_hash, owner_user_id, created_at, disabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (hostname, username, token_hash, update_slug, management_hash, owner_user_id, now),
            )
        return {
            "hostname": hostname,
            "username": username,
            "password": token,
            "update_slug": update_slug,
            "management_slug": management_slug,
        }

    def list_accounts(self, owner_user_id: int | None = None) -> list[dict[str, str | int | None]]:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            sql = """
            SELECT accounts.hostname, accounts.username, accounts.update_slug, accounts.owner_user_id,
                   accounts.created_at, accounts.disabled, records.ipv4, records.ipv6, records.updated_at
            FROM accounts
            LEFT JOIN records ON records.hostname = accounts.hostname
            """
            params: tuple[int, ...] = ()
            if owner_user_id is not None:
                sql += " WHERE accounts.owner_user_id = ?"
                params = (owner_user_id,)
            sql += " ORDER BY accounts.hostname"
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def get_account_by_slug(self, update_slug: str) -> dict[str, str | int | None] | None:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            account = conn.execute(
                """
                SELECT hostname, username, token_hash, update_slug, disabled FROM accounts
                WHERE update_slug = ?
                """,
                (update_slug,),
            ).fetchone()
        return dict(account) if account else None

    def get_account_by_management_slug(self, management_slug: str) -> dict[str, str | int | None] | None:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            account = conn.execute(
                """
                SELECT accounts.hostname, accounts.username, accounts.update_slug, accounts.owner_user_id,
                       accounts.created_at, accounts.disabled, records.ipv4, records.ipv6, records.updated_at
                FROM accounts
                LEFT JOIN records ON records.hostname = accounts.hostname
                WHERE accounts.management_hash = ?
                """,
                (hash_lookup_token(management_slug),),
            ).fetchone()
        return dict(account) if account else None

    def verify_account(self, hostname: str, username: str | None, token: str | None) -> bool:
        if not username or not token:
            return False
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            account = conn.execute(
                """
                SELECT token_hash, disabled FROM accounts
                WHERE hostname = ? AND username = ?
                """,
                (hostname, username),
            ).fetchone()
        if not account or account["disabled"]:
            return False
        return verify_secret(token, account["token_hash"])

    def delete_account(self, hostname: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM accounts WHERE hostname = ?", (hostname,))
            conn.execute("DELETE FROM records WHERE hostname = ?", (hostname,))

    def create_domain_challenge(self, domain: str, owner_user_id: int | None = None) -> dict[str, str]:
        token = f"ff-ddns-{secrets.token_urlsafe(24)}"
        claim_secret = secrets.token_urlsafe(32)
        claim_hash = hash_lookup_token(claim_secret)
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            existing = conn.execute("SELECT owner_user_id, verified_at FROM domain_challenges WHERE domain = ?", (domain,)).fetchone()
            if existing and existing[1]:
                raise sqlite3.IntegrityError("domain is already verified")
            if existing and owner_user_id is not None and existing[0] is not None and int(existing[0]) != owner_user_id:
                raise sqlite3.IntegrityError("domain challenge belongs to another user")
            conn.execute(
                """
                INSERT INTO domain_challenges(domain, token, claim_hash, owner_user_id, created_at, verified_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                ON CONFLICT(domain) DO UPDATE SET
                  token=excluded.token,
                  claim_hash=excluded.claim_hash,
                  owner_user_id=excluded.owner_user_id,
                  created_at=excluded.created_at,
                  verified_at=NULL
                """,
                (domain, token, claim_hash, owner_user_id, now),
            )
        return {"domain": domain, "token": token, "claim_secret": claim_secret}

    def verify_domain_challenge(self, domain: str, owner_user_id: int | None = None) -> dict[str, str | None] | None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            sql = "SELECT domain, token, verified_at FROM domain_challenges WHERE domain = ?"
            params: tuple[str, ...] | tuple[str, int] = (domain,)
            if owner_user_id is not None:
                sql += " AND owner_user_id = ?"
                params = (domain, owner_user_id)
            challenge = conn.execute(sql, params).fetchone()
            if not challenge:
                return None
            if owner_user_id is not None:
                conn.execute("UPDATE domain_challenges SET verified_at = ? WHERE domain = ? AND owner_user_id = ?", (now, domain, owner_user_id))
            else:
                conn.execute("UPDATE domain_challenges SET verified_at = ? WHERE domain = ?", (now, domain))
        result = dict(challenge)
        result["verified_at"] = now
        return result

    def get_domain_challenge(
        self,
        domain: str,
        owner_user_id: int | None = None,
        claim_secret: str | None = None,
    ) -> dict[str, str | None] | None:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            sql = "SELECT domain, token, verified_at FROM domain_challenges WHERE domain = ?"
            params: tuple[str, ...] | tuple[str, int] = (domain,)
            if owner_user_id is not None:
                sql += " AND owner_user_id = ?"
                params = (domain, owner_user_id)
            elif claim_secret is not None:
                sql += " AND claim_hash = ?"
                params = (domain, hash_lookup_token(claim_secret))
            challenge = conn.execute(sql, params).fetchone()
        return dict(challenge) if challenge else None

    def is_domain_verified(
        self,
        domain: str,
        owner_user_id: int | None = None,
        claim_secret: str | None = None,
    ) -> bool:
        with self.connect() as conn:
            sql = "SELECT verified_at FROM domain_challenges WHERE domain = ?"
            params: tuple[str, ...] | tuple[str, int] = (domain,)
            if owner_user_id is not None:
                sql += " AND owner_user_id = ?"
                params = (domain, owner_user_id)
            elif claim_secret is not None:
                sql += " AND claim_hash = ?"
                params = (domain, hash_lookup_token(claim_secret))
            verified_at = conn.execute(sql, params).fetchone()
        return bool(verified_at and verified_at[0])

    def count_user_accounts(self, owner_user_id: int) -> int:
        with self.connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM accounts WHERE owner_user_id = ? AND disabled = 0", (owner_user_id,)).fetchone()
        return int(row[0])

    def create_user(self, email: str, password: str, invite_code: str | None, require_invite: bool) -> dict[str, str | int]:
        now = datetime.now(UTC).isoformat()
        password_hash = hash_secret(password)
        with self.connect() as conn:
            if require_invite:
                invite = conn.execute(
                    "SELECT code, used_at FROM invites WHERE code = ?",
                    (invite_code or "",),
                ).fetchone()
                if not invite or invite[1]:
                    raise ValueError("invalid invite code")
            cursor = conn.execute(
                """
                INSERT INTO users(email, password_hash, created_at, disabled)
                VALUES (?, ?, ?, 0)
                """,
                (email, password_hash, now),
            )
            user_id = int(cursor.lastrowid)
            if require_invite and invite_code:
                conn.execute("UPDATE invites SET used_at = ?, used_by_user_id = ? WHERE code = ?", (now, user_id, invite_code))
        return {"id": user_id, "email": email}

    def authenticate_user(self, email: str, password: str) -> dict[str, str | int] | None:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            user = conn.execute(
                "SELECT id, email, password_hash, disabled FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        if not user or user["disabled"] or not verify_secret(password, user["password_hash"]):
            return None
        return {"id": int(user["id"]), "email": str(user["email"])}

    def get_user(self, user_id: int) -> dict[str, str | int] | None:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            user = conn.execute("SELECT id, email, disabled FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["disabled"]:
            return None
        return {"id": int(user["id"]), "email": str(user["email"])}

    def create_invite(self) -> dict[str, str]:
        code = secrets.token_urlsafe(18)
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            conn.execute("INSERT INTO invites(code, created_at) VALUES (?, ?)", (code, now))
        return {"code": code}

    def list_invites(self) -> list[dict[str, str | None]]:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT code, created_at, used_at FROM invites ORDER BY created_at DESC LIMIT 50"
            ).fetchall()
        return [dict(row) for row in rows]

    def list_records(self) -> list[dict[str, str | None]]:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT hostname, ipv4, ipv6, updated_at FROM records ORDER BY hostname").fetchall()
        return [dict(row) for row in rows]

    def log_update_event(
        self,
        hostname: str,
        ipv4: str | None,
        ipv6: str | None,
        status: str,
        detail: str,
        source_ip: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO update_events(hostname, ipv4, ipv6, status, detail, source_ip, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (hostname, ipv4, ipv6, status, detail[:500], source_ip, datetime.now(UTC).isoformat()),
            )

    def list_update_events(self, limit: int = 100) -> list[dict[str, str | None]]:
        with self.connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT hostname, ipv4, ipv6, status, detail, source_ip, created_at
                FROM update_events
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def allow_rate_limit(self, key: str, limit: int) -> bool:
        now = int(time.time())
        window = now // 60
        with self.connect() as conn:
            conn.execute("DELETE FROM rate_limits WHERE window < ?", (window - 2,))
            row = conn.execute(
                "SELECT count FROM rate_limits WHERE key = ? AND window = ?",
                (key, window),
            ).fetchone()
            count = int(row[0]) if row else 0
            if count >= limit:
                return False
            conn.execute(
                """
                INSERT INTO rate_limits(key, window, count)
                VALUES (?, ?, 1)
                ON CONFLICT(key, window) DO UPDATE SET count=count + 1
                """,
                (key, window),
            )
        return True

    def cleanup(self, challenge_hours: int) -> None:
        cutoff = datetime.now(UTC) - timedelta(hours=challenge_hours)
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM domain_challenges WHERE verified_at IS NULL AND created_at < ?",
                (cutoff.isoformat(),),
            )

    def _init_db(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                  hostname TEXT PRIMARY KEY,
                  ipv4 TEXT,
                  ipv6 TEXT,
                  updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS update_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  hostname TEXT NOT NULL,
                  ipv4 TEXT,
                  ipv6 TEXT,
                  status TEXT NOT NULL,
                  detail TEXT NOT NULL,
                  source_ip TEXT NOT NULL,
                  created_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_update_events_created_at ON update_events(created_at)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limits (
                  key TEXT NOT NULL,
                  window INTEGER NOT NULL,
                  count INTEGER NOT NULL,
                  PRIMARY KEY(key, window)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                  hostname TEXT PRIMARY KEY,
                  username TEXT NOT NULL,
                  token_hash TEXT NOT NULL,
                  update_slug TEXT NOT NULL UNIQUE,
                  management_hash TEXT UNIQUE,
                  owner_user_id INTEGER,
                  created_at TEXT NOT NULL,
                  disabled INTEGER NOT NULL DEFAULT 0,
                  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
                )
                """
            )
            _ensure_column(conn, "accounts", "update_slug", "TEXT")
            _ensure_column(conn, "accounts", "management_hash", "TEXT")
            _ensure_column(conn, "accounts", "owner_user_id", "INTEGER")
            for row in conn.execute("SELECT hostname FROM accounts WHERE update_slug IS NULL OR update_slug = ''"):
                conn.execute("UPDATE accounts SET update_slug = ? WHERE hostname = ?", (secrets.token_urlsafe(32), row[0]))
            for row in conn.execute("SELECT hostname FROM accounts WHERE management_hash IS NULL OR management_hash = ''"):
                conn.execute("UPDATE accounts SET management_hash = ? WHERE hostname = ?", (hash_lookup_token(secrets.token_urlsafe(32)), row[0]))
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_update_slug ON accounts(update_slug)")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_management_hash ON accounts(management_hash)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS domain_challenges (
                  domain TEXT PRIMARY KEY,
                  token TEXT NOT NULL,
                  claim_hash TEXT,
                  owner_user_id INTEGER,
                  created_at TEXT NOT NULL,
                  verified_at TEXT,
                  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            _ensure_column(conn, "domain_challenges", "claim_hash", "TEXT")
            _ensure_column(conn, "domain_challenges", "owner_user_id", "INTEGER")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL UNIQUE,
                  password_hash TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  disabled INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS invites (
                  code TEXT PRIMARY KEY,
                  created_at TEXT NOT NULL,
                  used_at TEXT,
                  used_by_user_id INTEGER,
                  FOREIGN KEY(used_by_user_id) REFERENCES users(id) ON DELETE SET NULL
                )
                """
            )


def _default_username(hostname: str) -> str:
    label = hostname.split(".", 1)[0]
    import re

    return re.sub(r"[^a-z0-9_.-]", "-", label.lower()) or "fritzbox"


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
