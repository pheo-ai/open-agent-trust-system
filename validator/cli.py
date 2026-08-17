"""Command-line validator for Open Agent Trust profile documents."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import (
    validate_action_receipt,
    validate_document,
    validate_policy,
    validate_skill,
    validate_transition,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Open Agent Trust JSON")
    parser.add_argument("kind", choices=["skill", "policy", "attestation", "action_receipt", "transition"])
    parser.add_argument("path", type=Path)
    args = parser.parse_args()

    document = json.loads(args.path.read_text())
    if args.kind == "skill":
        validate_skill(document)
    elif args.kind == "policy":
        validate_policy(document)
    elif args.kind == "action_receipt":
        validate_action_receipt(document)
    elif args.kind == "transition":
        validate_transition(document)
    else:
        validate_document(document, args.kind)
    print(f"valid {args.kind}: {args.path}")


if __name__ == "__main__":
    main()
