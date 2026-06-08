"""HTTP helper functions copied from Sally and kept schema-agnostic."""

from base64 import urlsafe_b64encode as encodeB64
from collections import namedtuple

import falcon
from http_sfv import Dictionary
from keri.help import helping

Inputage = namedtuple("Inputage", "name fields created keyid alg expires nonce context")


def normalize(param):
    return str(param).strip()


def cors_middleware():
    return falcon.CORSMiddleware(
        allow_origins="*",
        allow_credentials="*",
        expose_headers=cesr_headers(),
    )


def cesr_headers():
    return ["cesr-attachment", "cesr-date", "content-type"]


def siginput(hab, name, method, path, headers, fields, expires=None, nonce=None, alg=None, keyid=None, context=None):
    items = []
    ifields = []
    for field in fields:
        if field.startswith("@"):
            if field == "@method":
                items.append(f'"{field}": {method}')
                ifields.append(field)
            elif field == "@path":
                items.append(f'"{field}": {path}')
                ifields.append(field)
            continue

        lower = field.lower()
        if lower not in headers:
            continue
        ifields.append(lower)
        items.append(f'"{lower}": {normalize(headers[lower])}')

    sid = Dictionary()
    sid[name] = ifields
    now = helping.nowUTC()
    sid[name].params["created"] = int(now.timestamp())

    values = [f"({' '.join(ifields)})", f"created={int(now.timestamp())}"]
    if expires is not None:
        values.append(f"expires={expires}")
        sid[name].params["expires"] = expires
    if nonce is not None:
        values.append(f"nonce={nonce}")
        sid[name].params["nonce"] = nonce
    if keyid is not None:
        values.append(f"keyid={keyid}")
        sid[name].params["keyid"] = keyid
    if context is not None:
        values.append(f"context={context}")
        sid[name].params["context"] = context
    if alg is not None:
        values.append(f"alg={alg}")
        sid[name].params["alg"] = alg

    items.append(f'"@signature-params: {";".join(values)}"')
    ser = "\n".join(items).encode("utf-8")
    sigers = hab.sign(ser=ser, verfers=hab.kever.verfers, indexed=False)
    return {"Signature-Input": f"{sid}"}, Unqualified(raw=sigers[0].raw)


class Unqualified:
    def __init__(self, raw):
        self._raw = raw

    @property
    def raw(self):
        return self._raw

    @property
    def qb64(self):
        return self.qb64b.decode("utf-8")

    @property
    def qb64b(self):
        return encodeB64(self.raw)
