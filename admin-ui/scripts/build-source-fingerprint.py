#!/usr/bin/env python3
"""Write a host-independent fingerprint for the admin UI build inputs."""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADMIN_UI = ROOT / "admin-ui"
FINGERPRINT = ADMIN_UI / "build-source.sha256"
EXCLUDED_DIRS = {"dist", "node_modules", "target", "__pycache__"}


def main() -> None:
    files = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")]
    cargo_config = ROOT / ".cargo"
    if cargo_config.exists():
        files.extend(
            path
            for path in cargo_config.iterdir()
            if path.is_file() and path.name in {"config", "config.toml"}
        )

    for path in ADMIN_UI.rglob("*"):
        relative = path.relative_to(ADMIN_UI)
        if (
            path.is_file()
            and not EXCLUDED_DIRS.intersection(relative.parts)
            and path.name != ".DS_Store"
            and not path.name.startswith("._")
            and path != FINGERPRINT
        ):
            files.append(path)

    digest = hashlib.sha256()
    for path in sorted(set(files), key=lambda item: item.relative_to(ROOT).as_posix()):
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")

    FINGERPRINT.write_text(f"{digest.hexdigest()}\n", encoding="utf-8")
    print(f"wrote {FINGERPRINT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
