"""Command-line validator for local profile documents."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import ValidationError, validate_document, validate_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Open Agent Trust JSON")
    parser.add_argument("kind", choices=("skill", "policy", "attestation", "action_receipt", "transition"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    document = json.loads(args.path.read_text())
    try:
        if args.kind == "policy":
            validate_policy(document)
        else:
            validate_document(document, args.kind)
    except ValidationError as error:
        parser.error(str(error))
    print(f"valid {args.kind}: {args.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
