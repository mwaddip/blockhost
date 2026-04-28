"""Engine manifest loader — single source of truth for /usr/share/blockhost/engine.json.

All consumers (admin panel, web installer, validation) load through here so
exception handling and field interpretation stay consistent.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Pattern

ENGINE_MANIFEST_PATH = Path('/usr/share/blockhost/engine.json')


@dataclass
class EngineManifest:
    """Parsed engine manifest with compiled regex constraints.

    Defaults match what consumers used to compute when the manifest was
    missing or unparseable, so callers don't need to special-case "no engine".
    """
    name: Optional[str] = None
    session_key: Optional[str] = None
    address_re: Optional[Pattern] = None
    signature_re: Optional[Pattern] = None
    token_re: Optional[Pattern] = None
    native_token: str = ''
    native_token_label: str = 'Native'
    address_placeholder: str = ''
    raw: dict = field(default_factory=dict)


def _compile(pattern: Optional[str]) -> Optional[Pattern]:
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error:
        return None


def load_engine_manifest(path: Path = ENGINE_MANIFEST_PATH) -> EngineManifest:
    """Load and parse the engine manifest. Returns defaults if missing/invalid."""
    try:
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return EngineManifest()

    constraints = manifest.get('constraints', {})
    config_keys = manifest.get('config_keys', {})

    return EngineManifest(
        name=manifest.get('name'),
        session_key=config_keys.get('session_key'),
        address_re=_compile(constraints.get('address_pattern')),
        signature_re=_compile(constraints.get('signature_pattern')),
        token_re=_compile(constraints.get('token_pattern')),
        native_token=constraints.get('native_token', ''),
        native_token_label=constraints.get('native_token_label', 'Native'),
        address_placeholder=constraints.get('address_placeholder', ''),
        raw=manifest,
    )
