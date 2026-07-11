"""Remote-Hand ↔ Flutter wire protocol (schema-driven dynamic form).

CDP-free method 3: the relay drives a vanilla Chromium on an X display via
OS-level input (XTEST/xdotool) and reads the screen visually. This module only
defines the messages exchanged with Flutter over the existing ws.Hub — it holds
NO browser-automation logic and NO CDP.

Sensitive fields (password, SMS code) are NEVER sent in cleartext `values`;
Flutter puts them in `sealed` (NaCl sealed_box on the relay's ephemeral session
pubkey — see RELAY-REMOTE-HAND-PLAN.md §10.1). Cleartext here is only for
non-sensitive fields (login, phone) that the user supplies anyway.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class PageState(str, Enum):
    """What the login page currently shows (classified visually, no DOM/CDP)."""
    EMAIL = "email"; PASSWORD = "password"; CONSENT = "consent"
    PHONE = "phone"; SEND_CODE = "send_code"; SMS = "sms_code"; CAPTCHA = "captcha"
    UNVERIFIED_APP = "unverified_app"; SUCCESS = "success"; ERROR = "error"; UNKNOWN = "unknown"


@dataclass
class Field:
    """One dynamic form field rendered by Flutter."""
    name: str
    label: str                      # label copied from the real Google field
    kind: str = "text"              # text|password|tel|code|captcha_image|captcha_live
    value: str = ""
    hint: str = ""
    sensitive: bool = False         # True → Flutter must send via `sealed`, not `values`

    def __post_init__(self) -> None:
        if self.kind in ("password", "code"):  # credentials/OTP are always sealed
            self.sensitive = True


def rh_hello(session_id: str, relay_pubkey_b64: str) -> dict[str, Any]:
    """First message: gives Flutter the ephemeral pubkey to seal secrets to."""
    return {"type": "rh_hello", "session_id": session_id, "relay_pubkey": relay_pubkey_b64}


def rh_prompt(session_id: str, request_id: str, step: str, title: str,
              fields: list[Field], image_b64: str | None = None,
              region: dict | None = None, level: str = "info") -> dict[str, Any]:
    """Ask the user to fill `fields`. `image_b64` carries a tightly-cropped
    captcha (§8.1: challenge must fill the view, not sit in an empty screen)."""
    msg: dict[str, Any] = {"type": "rh_prompt", "session_id": session_id,
                           "request_id": request_id, "step": step, "title": title,
                           "fields": [asdict(f) for f in fields], "level": level}
    if image_b64 is not None:
        msg["image"] = image_b64
    if region is not None:
        msg["region"] = region
    return msg


def rh_state(session_id: str, request_id: str, state: str, message: str = "") -> dict[str, Any]:
    """Progress/terminal signal: working|need_input|success|error."""
    return {"type": "rh_state", "session_id": session_id, "request_id": request_id,
            "state": state, "message": message}


@dataclass
class RhInput:
    """Parsed Flutter → relay submission."""
    session_id: str
    request_id: str
    step: str
    values: dict[str, str] = field(default_factory=dict)   # non-sensitive only
    sealed: str | None = None                              # base64 sealed_box for secrets
    gesture: list[dict] = field(default_factory=list)      # [{x,y,t,down}] for captcha replay

    @staticmethod
    def parse(raw: dict[str, Any]) -> "RhInput":
        if raw.get("type") != "rh_input":
            raise ValueError(f"not an rh_input message: type={raw.get('type')!r}")
        return RhInput(session_id=raw.get("session_id", ""), request_id=raw.get("request_id", ""),
                       step=raw.get("step", ""), values=dict(raw.get("values", {})),
                       sealed=raw.get("sealed"), gesture=list(raw.get("gesture", [])))
