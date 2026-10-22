"""``hindsight-acl`` command line: validate the access file, create keys, explain decisions."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import secrets
import sys
from importlib import resources

from . import __version__
from .config import AccessConfigError, access_file_path, load_config
from .policy import describe


def _cmd_check(args: argparse.Namespace) -> int:
    path = access_file_path(args.file)
    try:
        cfg = load_config(path)
    except AccessConfigError as exc:
        print(f"INVALID {path}", file=sys.stderr)
        for err in exc.errors:
            print(f"  error: {err}", file=sys.stderr)
        return 1
    for warning in cfg.warnings:
        print(f"  warning: {warning}", file=sys.stderr)
    print(f"OK {path}: {len(cfg.identities)} identities")
    types = ", ".join(f"{t}={p or '(no own space)'}" for t, p in cfg.types.items())
    print(f"types: {types}")
    for ident in cfg.identities.values():
        print(f"\n{ident.id}  [{ident.type}{', admin' if ident.admin else ''}]")
        if ident.description:
            print(f"  description: {ident.description}")
        print(f"  own space:   {ident.own_space or '-'}")
        print(f"  write tag:   {ident.write_tag}")
        if ident.admin:
            print("  access:      every bank (rw)")
        for g in ident.grants:
            print(f"  grant:       {g.access.label():<3} {', '.join(g.banks)}")
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    key = secrets.token_urlsafe(args.bytes)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    print("# Store the key in your password manager; it is not shown again.", file=sys.stderr)
    print(f"key:        {key}")
    print(f"key_sha256: \"{digest}\"")
    return 0


def _cmd_hash(args: argparse.Namespace) -> int:
    key = sys.stdin.readline().rstrip("\n") if not sys.stdin.isatty() else getpass.getpass("key: ")
    if not key:
        print("empty key", file=sys.stderr)
        return 1
    print(hashlib.sha256(key.encode("utf-8")).hexdigest())
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        cfg = load_config(access_file_path(args.file))
    except AccessConfigError as exc:
        print(exc, file=sys.stderr)
        return 1
    for bank in args.bank:
        print(describe(cfg, args.identity, bank))
    return 0


def _cmd_schema(args: argparse.Namespace) -> int:
    text = resources.files("hindsight_ext_acl").joinpath("access.schema.json").read_text(encoding="utf-8")
    json.loads(text)  # sanity
    print(text, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hindsight-acl", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check", help="validate the access file and print the effective rules")
    p.add_argument("file", nargs="?", help="default: $HINDSIGHT_API_TENANT_ACCESS_FILE or /etc/hindsight/access.yaml")
    p.set_defaults(func=_cmd_check)

    p = sub.add_parser("keygen", help="generate a key and its key_sha256 line")
    p.add_argument("--bytes", type=int, default=32, help="random bytes (default 32)")
    p.set_defaults(func=_cmd_keygen)

    p = sub.add_parser("hash", help="print the sha256 of a key read from stdin")
    p.set_defaults(func=_cmd_hash)

    p = sub.add_parser("explain", help="show the access an identity gets on one or more banks")
    p.add_argument("identity")
    p.add_argument("bank", nargs="+")
    p.add_argument("-f", "--file", help="access file")
    p.set_defaults(func=_cmd_explain)

    p = sub.add_parser("schema", help="print the JSON Schema of the access file")
    p.set_defaults(func=_cmd_schema)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

