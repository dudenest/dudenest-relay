"""Per-session end-to-end encryption of credentials (RELAY-REMOTE-HAND-PLAN.md §10.1).

TLS terminates at HAProxy (the edge sees plaintext), so TLS alone is NOT enough
for the Google password. We add an application-layer sealed box: the sidecar
generates an ephemeral X25519 keypair per session, hands the public key to Flutter
(rh_hello), Flutter seals secrets with `crypto_box_seal`, and only this process —
holding the private key in memory — can open them. HAProxy/hub/provisioner see
ciphertext only. Zero-knowledge for the password, consistent with the rest of Dudenest.

The private key never leaves the process and is best-effort wiped on close.
"""
from __future__ import annotations
import base64

from nacl.public import PrivateKey, SealedBox


class SessionKeys:
    """Ephemeral X25519 keypair for one Remote-Hand session."""

    def __init__(self) -> None:
        self._sk: PrivateKey | None = PrivateKey.generate()

    @property
    def public_key_b64(self) -> str:
        """Base64 pubkey to embed in rh_hello; Flutter seals secrets to this."""
        assert self._sk is not None, "session keys already wiped"
        return base64.b64encode(bytes(self._sk.public_key)).decode()

    def unseal(self, sealed_b64: str) -> str:
        """Open a sealed_box ciphertext from Flutter → plaintext secret."""
        assert self._sk is not None, "session keys already wiped"
        plaintext = SealedBox(self._sk).decrypt(base64.b64decode(sealed_b64))
        return plaintext.decode()

    def wipe(self) -> None:
        """Best-effort drop of the private key (Python can't guarantee zeroing)."""
        self._sk = None


def seal_for(public_key_b64: str, plaintext: str) -> str:
    """Seal a secret to a session pubkey (what Flutter does; here for tests)."""
    from nacl.public import PublicKey
    pk = PublicKey(base64.b64decode(public_key_b64))
    return base64.b64encode(SealedBox(pk).encrypt(plaintext.encode())).decode()
