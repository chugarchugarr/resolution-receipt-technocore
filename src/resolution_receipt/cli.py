"""Command-line interface for Resolution Receipt artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .core import (
    ReceiptError,
    create_key,
    create_policy_commitment,
    hash_object,
    load_json,
    sign_envelope,
    technocore_record_request,
    technocore_request,
    verify_bundle,
    verify_envelope,
    verify_technocore_record,
    verify_technocore_request,
    write_json,
)


def _emit(value: Any) -> None:
    json.dump(value, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
    sys.stdout.write("\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="resolution-receipt")
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="create an isolated Ed25519 did:key")
    keygen.add_argument("--out", required=True)
    keygen.add_argument("--label", required=True)

    commit = commands.add_parser(
        "commit-policy", help="commit to a sealed private policy"
    )
    commit.add_argument("--policy", required=True)
    commit.add_argument("--salt", required=True)
    commit.add_argument("--out", required=True)

    sign = commands.add_parser("sign", help="sign a JSON payload")
    sign.add_argument("--kind", required=True)
    sign.add_argument("--payload", required=True)
    sign.add_argument("--key", required=True)
    sign.add_argument("--out", required=True)

    verify = commands.add_parser("verify", help="verify one signed JSON object")
    verify.add_argument("--input", required=True)
    verify.add_argument("--kind")

    digest = commands.add_parser("hash", help="hash a JSON object canonically")
    digest.add_argument("--input", required=True)

    request = commands.add_parser(
        "technocore-request", help="create a signed Technocore write request"
    )
    request.add_argument("--room", required=True)
    request.add_argument("--nonce", required=True)
    request.add_argument("--text", required=True)
    request.add_argument("--key", required=True)
    request.add_argument("--out", required=True)

    verify_request = commands.add_parser(
        "verify-technocore", help="verify a signed Technocore request"
    )
    verify_request.add_argument("--room", required=True)
    verify_request.add_argument("--input", required=True)

    record_request = commands.add_parser(
        "technocore-record-request",
        help="create a self-contained signed Technocore record request",
    )
    record_request.add_argument("--room", required=True)
    record_request.add_argument("--nonce", required=True)
    record_request.add_argument("--body", required=True)
    record_request.add_argument("--key", required=True)
    record_request.add_argument("--out", required=True)

    verify_record = commands.add_parser(
        "verify-technocore-record",
        help="verify one public Technocore JSON record",
    )
    verify_record.add_argument("--room", required=True)
    verify_record.add_argument("--input", required=True)

    bundle = commands.add_parser(
        "verify-bundle", help="verify the complete receipt bundle"
    )
    bundle.add_argument("--manifest", required=True)
    bundle.add_argument("--claim", required=True)
    bundle.add_argument("--verdict", required=True)
    bundle.add_argument("--receipt", required=True)

    return parser


def _run(args: argparse.Namespace) -> None:
    if args.command == "keygen":
        _emit(
            {
                "did": create_key(args.out, label=args.label),
                "private_key_file": args.out,
            }
        )
    elif args.command == "commit-policy":
        commitment = create_policy_commitment(args.policy, args.salt)
        write_json(args.out, commitment)
        _emit(commitment)
    elif args.command == "sign":
        envelope = sign_envelope(args.kind, load_json(args.payload), args.key)
        write_json(args.out, envelope)
        _emit(
            {
                "hash": hash_object(envelope),
                "out": args.out,
                "signer": envelope["signer"],
            }
        )
    elif args.command == "verify":
        envelope = load_json(args.input)
        verify_envelope(envelope, expected_kind=args.kind)
        _emit(
            {
                "hash": hash_object(envelope),
                "kind": envelope["kind"],
                "signer": envelope["signer"],
                "valid": True,
            }
        )
    elif args.command == "hash":
        _emit({"hash": hash_object(load_json(args.input))})
    elif args.command == "technocore-request":
        value = technocore_request(
            room=args.room, nonce=args.nonce, text=args.text, key_path=args.key
        )
        write_json(args.out, value)
        _emit({"did": value["did"], "out": args.out})
    elif args.command == "verify-technocore":
        value = load_json(args.input)
        verify_technocore_request(room=args.room, request=value)
        _emit({"did": value["did"], "valid": True})
    elif args.command == "technocore-record-request":
        value = technocore_record_request(
            room=args.room,
            nonce=args.nonce,
            body=args.body,
            key_path=args.key,
        )
        write_json(args.out, value)
        _emit({"did": value["did"], "out": args.out})
    elif args.command == "verify-technocore-record":
        result = verify_technocore_record(
            room=args.room,
            record=load_json(args.input),
        )
        _emit({**result, "valid": True})
    elif args.command == "verify-bundle":
        _emit(
            verify_bundle(
                manifest=load_json(args.manifest),
                claim=load_json(args.claim),
                verdict=load_json(args.verdict),
                receipt=load_json(args.receipt),
            )
        )
    else:
        raise ReceiptError("unknown command")


def main() -> None:
    try:
        _run(_parser().parse_args())
    except (ReceiptError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
