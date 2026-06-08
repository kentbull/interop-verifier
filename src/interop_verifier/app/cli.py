"""Command line entrypoint."""

import argparse
import json

from keri.app import configing, habbing, keeping

import interop_verifier
from interop_verifier.core import serving
from interop_verifier.core.policy import VerificationPolicy


def main():
    parser = argparse.ArgumentParser(prog="interop-verifier")
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start", help="Start the interop verifier service")
    start.add_argument("-p", "--http", default=9723, type=int)
    start.add_argument("-n", "--name", default="interop-verifier")
    start.add_argument("-b", "--base", default="")
    start.add_argument("--head-dir", dest="headDirPath", default=None)
    start.add_argument("-a", "--alias", required=True)
    start.add_argument("-s", "--salt")
    start.add_argument("--passcode", dest="bran", default=None)
    start.add_argument("-i", "--incept-file", dest="inceptFile", default=None)
    start.add_argument("-c", "--config-dir", dest="configDir", default=None)
    start.add_argument("-f", "--config-file", dest="configFile", default=None)
    start.add_argument("-w", "--web-hook", dest="webHook", required=True)
    start.add_argument("--policy", dest="policyFile", default=None)
    start.add_argument("--schema", dest="schemas", action="append", default=[])
    start.add_argument("-r", "--retry-delay", default=3, type=int)
    start.add_argument("-e", "--escrow-timeout", default=10, type=int)
    start.add_argument("--no-clear-escrows", action="store_true", default=False)
    start.set_defaults(handler=start_command)

    version = sub.add_parser("version", help="Print version")
    version.set_defaults(handler=lambda args: print(interop_verifier.__version__))

    args = parser.parse_args()
    args.handler(args)


def start_command(args):
    hby = init_habery(
        name=args.name,
        base=args.base,
        bran=args.bran,
        config_file=args.configFile,
        config_dir=args.configDir,
        salt=args.salt,
        head_dir_path=args.headDirPath,
    )
    incept_args = {
        "name": args.name,
        "base": args.base,
        "alias": args.alias,
        "bran": args.bran,
        "incept_file": args.inceptFile,
        "config_dir": args.configDir,
    }
    hab = serving.incept_if_new(hby, args.alias, incept_args)
    serving.load_schemas(hby, args.schemas)
    policy = VerificationPolicy(load_policy(args.policyFile))
    doers = serving.setupDoers(
        hby,
        hab,
        alias=args.alias,
        http_port=args.http,
        hook=args.webHook,
        policy=policy,
        timeout=args.escrow_timeout,
        retry=args.retry_delay,
        clear_escrows=not args.no_clear_escrows,
        head_dir_path=args.headDirPath,
    )
    print(f"Interop verifier {hab.pre} listening on http://127.0.0.1:{args.http}", flush=True)
    serving.run_doers(doers)


def init_habery(name, base, bran, config_file, config_dir, salt, head_dir_path=None):
    ks = keeping.Keeper(name=name, base=base, temp=False, reopen=True, headDirPath=head_dir_path)
    aeid = ks.gbls.get("aeid")
    if aeid is None:
        cf = None
        if config_file is not None:
            cf = configing.Configer(name=config_file, base=base, headDirPath=config_dir, temp=False, reopen=True, clear=False)
        return habbing.Habery(
            name=name,
            base=base,
            bran=bran,
            cf=cf,
            ks=ks,
            salt=salt if salt else None,
            headDirPath=head_dir_path,
        )

    return habbing.Habery(name=name, base=base, bran=bran, ks=ks, headDirPath=head_dir_path)


def load_policy(path):
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


if __name__ == "__main__":
    main()
