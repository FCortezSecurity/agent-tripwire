"""Bounded detection of observed tokens sent as Base64 fragments."""

import base64
import hashlib
import re
from collections import OrderedDict

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{11,127}")
# Individual fragments can be shorter than 8 characters.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{1,128}={0,2}\Z")


class CrossCallEgressDetector:
    """Targeted Base64-fragment matching, not general-purpose DLP."""

    MAX_TOKENS = 256
    MAX_RESULT_CHARS = 16_384
    MAX_STREAM_CHARS = 256

    def __init__(self):
        self._token_hashes: OrderedDict[bytes, None] = OrderedDict()
        self._stream = ""
        self._recipient = ""

    @staticmethod
    def _fingerprint(value: str) -> bytes:
        return hashlib.sha256(value.encode("utf-8")).digest()

    def observe_result(self, text: str) -> None:
        """Remember hashes of sufficiently long tokens in a result."""
        for match in _TOKEN_RE.finditer(text[: self.MAX_RESULT_CHARS]):
            fingerprint = self._fingerprint(match.group(0))
            self._token_hashes[fingerprint] = None
            self._token_hashes.move_to_end(fingerprint)

            while len(self._token_hashes) > self.MAX_TOKENS:
                self._token_hashes.popitem(last=False)

    def _stream_matches(self, candidate: str) -> bool:
        """Decode the accumulated Base64 stream and check for observed tokens."""
        chars = candidate.rstrip("=")
        if not chars or not re.fullmatch(r"[A-Za-z0-9+/]+", chars):
            return False

        # Restore padding for the accumulated stream, not each fragment.
        padded = chars + "=" * ((-len(chars)) % 4)

        try:
            decoded = base64.b64decode(padded, validate=True)
        except (ValueError, base64.binascii.Error):
            return False

        # Observed tokens are ASCII; latin-1 preserves bytes without decode errors.
        text = decoded.decode("latin-1")
        return any(
            self._fingerprint(match.group(0)) in self._token_hashes
            for match in _TOKEN_RE.finditer(text)
        )

    def would_leak(self, body: str, recipient: str) -> bool:
        """Inspect a candidate without changing committed state."""
        if not isinstance(body, str) or not _BASE64_RE.fullmatch(body):
            return False

        prefix = self._stream if recipient == self._recipient else ""
        candidate = prefix.rstrip("=") + body.rstrip("=")

        # Align left-side truncation to Base64's 4-character boundaries.
        if len(candidate) > self.MAX_STREAM_CHARS:
            excess = len(candidate) - self.MAX_STREAM_CHARS
            drop = excess + (-excess) % 4
            candidate = candidate[drop:]

        return self._stream_matches(candidate)

    def commit_outbound(self, body: str, recipient: str) -> None:
        """Update bounded history only after an outbound call succeeds."""
        if not isinstance(body, str) or not _BASE64_RE.fullmatch(body):
            self._stream = ""
            self._recipient = ""
            return

        if recipient != self._recipient:
            combined = body.rstrip("=")
        else:
            combined = self._stream.rstrip("=") + body.rstrip("=")

        if len(combined) > self.MAX_STREAM_CHARS:
            excess = len(combined) - self.MAX_STREAM_CHARS
            drop = excess + (-excess) % 4
            combined = combined[drop:]

        self._stream = combined
        self._recipient = recipient
