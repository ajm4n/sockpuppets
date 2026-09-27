"""Per-operator password auth for the SockPuppets GUI."""

import hashlib
import hmac
import secrets
from fastapi import Request, HTTPException


def _hash_password(password: str) -> str:
    """Hash a password with SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


class OperatorStore:
    """In-memory store mapping operator names to password hashes and session tokens."""

    def __init__(self):
        self._operators: dict[str, dict] = {}  # name -> {password_hash, must_change}
        self._sessions: dict[str, str] = {}    # session_token_hash -> operator_name

    def add(self, name: str, password: str, must_change: bool = True):
        """Create an operator with an explicit password."""
        self._operators[name] = {
            "password_hash": _hash_password(password),
            "must_change": must_change,
        }

    def verify(self, name: str, password: str) -> tuple[str | None, bool]:
        """Verify credentials. Returns (operator_name, must_change) or (None, False)."""
        entry = self._operators.get(name)
        if entry is None:
            return None, False
        if hmac.compare_digest(entry["password_hash"], _hash_password(password)):
            return name, entry["must_change"]
        return None, False

    def change_password(self, name: str, new_password: str):
        """Set a new password, clear must_change, and revoke old sessions."""
        entry = self._operators.get(name)
        if entry is None:
            return
        entry["password_hash"] = _hash_password(new_password)
        entry["must_change"] = False
        self.revoke_sessions(name)

    def create_session(self, name: str) -> str:
        """Create a session token for an authenticated operator. Returns the raw token."""
        raw_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        self._sessions[token_hash] = name
        return raw_token

    def verify_session(self, token: str) -> str | None:
        """Verify a session token and return the operator name, or None."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return self._sessions.get(token_hash)

    def requires_password_change(self, name: str) -> bool:
        entry = self._operators.get(name)
        return entry is not None and entry.get("must_change", False)

    def revoke_sessions(self, name: str):
        """Revoke all sessions for a given operator."""
        self._sessions = {h: n for h, n in self._sessions.items() if n != name}

    def remove(self, name: str) -> bool:
        self.revoke_sessions(name)
        return self._operators.pop(name, None) is not None

    def list(self) -> list[str]:
        return list(self._operators.keys())

    def __len__(self):
        return len(self._operators)


# Singleton -- survives GUI restart within the same process
operators = OperatorStore()


class AuthMiddleware:
    """FastAPI dependency that validates session Bearer tokens against the operator store."""

    def __call__(self, request: Request):
        auth = request.headers.get("Authorization", "")
        token = request.query_params.get("token", "")

        if auth.startswith("Bearer "):
            token = auth[7:]

        if not token:
            raise HTTPException(status_code=401, detail="Missing auth token")

        name = operators.verify_session(token)
        if name is None:
            raise HTTPException(status_code=401, detail="Invalid auth token")

        if operators.requires_password_change(name):
            raise HTTPException(status_code=403, detail="Password change required")

        return name
