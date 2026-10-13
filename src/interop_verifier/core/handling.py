"""Generic Sally-style IPEX presentation and webhook handling."""

import datetime
import json
from base64 import urlsafe_b64encode as encodeB64
from urllib import parse

from hio.base import doing, Doer
from hio.core import http
from hio.help import Hict
from keri import kering
from keri.core import coring, serdering
from keri.end import ending
from keri.help import helping
from keri.peer import exchanging

from interop_verifier.core import httping
from interop_verifier.core.policy import VerificationPolicy, credential_payload, revocation_payload


def loadHandlers(cdb, hby, notifier, parser):
    return [PresentationProofHandler(cdb=cdb, hby=hby, notifier=notifier, parser=parser)]


class PresentationProofHandler(doing.Doer):
    """Processes IPEX grant notifications and parses embedded proof material."""

    def __init__(self, cdb, hby, notifier, parser, **kwa):
        self.cdb = cdb
        self.hby = hby
        self.notifier = notifier
        self.parser = parser
        super().__init__(**kwa)

    def processNotes(self):
        for keys, notice in self.cdb.items(self.notifier.noter.notes):
            attrs = notice.attrs
            route = attrs.get("r")
            if route in ("/exn/ipex/grant", "/ipex/grant"):
                said = attrs["d"]
                exn, pathed = exchanging.cloneMessage(self.hby, said=said)
                embeds = exn.ked["e"]

                for label in ("anc", "iss", "acdc"):
                    if label not in embeds:
                        continue
                    # Rehydrate in its protocol domain so the embedded version is preserved.
                    klas = serdering.SerderACDC if label == "acdc" else serdering.SerderKERI
                    serder = klas(sad=embeds[label])
                    attachment = pathed[label] if label in pathed else bytearray()
                    self.parser.parseOne(ims=bytearray(serder.raw) + attachment)

                acdc = embeds["acdc"]
                credential = acdc["d"]
                sender = acdc["i"]
                self.cdb.snd.pin(keys=(credential,), val=coring.Prefixer(qb64=sender))
                self.cdb.iss.pin(keys=(credential,), val=coring.Dater())

            self.notifier.noter.notes.rem(keys=keys)
        return False

    def recur(self, tyme):
        self.processNotes()
        return False


class Communicator(doing.DoDoer):
    """Moves verified credentials to webhook delivery queues and posts callbacks."""

    def __init__(self, hby, hab, cdb, reger, hook, policy=None, timeout=10, retry=3.0):
        self.hby = hby
        self.hab = hab
        self.cdb = cdb
        self.reger = reger
        self.hook = hook
        self.policy = policy or VerificationPolicy()
        self.timeout = timeout
        self.retry = retry
        self.clients = {}
        super().__init__(doers=[doing.doify(self.escrowDo)])

    def processPresentations(self):
        for (said,), dater in self.cdb.items(self.cdb.iss):
            now = helping.nowUTC()
            if now - dater.datetime > datetime.timedelta(minutes=self.timeout):
                self.cdb.iss.rem(keys=(said,))
                continue

            if self.reger.saved.get(keys=(said,)) is None:
                continue

            creder = self.reger.creds.get(keys=(said,))
            try:
                state = self.reger.tevers[creder.sad["ri"]].vcState(creder.said)
                if state is None or state.et not in (kering.Ilks.iss, kering.Ilks.bis):
                    raise kering.ValidationError(f"credential {creder.said} is not currently issued")
                self.policy.validate(creder)
            except kering.ValidationError:
                self.cdb.iss.rem(keys=(said,))
            else:
                self.cdb.recv.pin(keys=(said, dater.qb64), val=creder)
                self.cdb.iss.rem(keys=(said,))

    def processRevocations(self):
        for (said,), dater in self.cdb.items(self.cdb.rev):
            now = helping.nowUTC()
            if now - dater.datetime > datetime.timedelta(minutes=self.timeout):
                self.cdb.rev.rem(keys=(said,))
                continue

            creder = self.reger.creds.get(keys=(said,))
            if creder is None:
                continue
            state = self.reger.tevers[creder.sad["ri"]].vcState(creder.said)
            if state is None or state.et in (kering.Ilks.iss, kering.Ilks.bis):
                continue
            if state.et in (kering.Ilks.rev, kering.Ilks.brv):
                self.cdb.rev.rem(keys=(said,))
                self.cdb.revk.pin(keys=(said, dater.qb64), val=creder)

    def processReceived(self, db, action):
        for (said, dates), creder in self.cdb.items(db):
            if said not in self.clients:
                data = (
                    credential_payload(self.reger, creder, self.policy)
                    if action == "iss"
                    else revocation_payload(self.reger, creder, self.policy)
                )
                self.request(creder.said, creder.schema, action, creder.issuer, data)
                continue

            client, clientDoer = self.clients[said]
            if client.responses:
                response = client.responses.popleft()
                self.remove([clientDoer])
                client.close()
                del self.clients[said]

                if 200 <= response["status"] < 300:
                    db.rem(keys=(said, dates))
                    self.cdb.ack.pin(keys=(said,), val=creder)
                else:
                    dater = coring.Dater(qb64=dates)
                    if helping.nowUTC() - dater.datetime > datetime.timedelta(minutes=self.timeout):
                        db.rem(keys=(said, dates))

    def processAcks(self):
        for (said,), _ in self.cdb.items(self.cdb.ack):
            self.cdb.ack.rem(keys=(said,))

    def escrowDo(self, tymth, tock=1.0, **opts):
        self.wind(tymth)
        self.tock = tock
        _ = yield self.tock
        while True:
            self.processEscrows()
            yield self.retry

    def processEscrows(self):
        self.processPresentations()
        self.processRevocations()
        self.processReceived(db=self.cdb.recv, action="iss")
        self.processReceived(db=self.cdb.revk, action="rev")
        self.processAcks()

    def request(self, said, resource, action, actor, data):
        purl = parse.urlparse(self.hook)
        client = http.clienting.Client(hostname=purl.hostname, port=purl.port or 80)
        clientDoer = http.clienting.ClientDoer(client=client)
        self.extend([clientDoer])

        raw = json.dumps({"action": action, "actor": actor, "data": data}).encode("utf-8")
        headers = Hict([
            ("Content-Type", "application/json"),
            ("Content-Length", len(raw)),
            ("Connection", "close"),
            ("Sally-Resource", resource),
            ("Sally-Timestamp", helping.nowIso8601()),
        ])
        path = purl.path or "/"

        keyid = encodeB64(self.hab.kever.serder.verfers[0].raw).decode("utf-8")
        header, unq = httping.siginput(
            self.hab,
            "sig0",
            "POST",
            path,
            headers,
            fields=["Sally-Resource", "@method", "@path", "Sally-Timestamp"],
            alg="ed25519",
            keyid=keyid,
        )
        headers.extend(header)
        signage = ending.Signage(
            markers={"sig0": unq},
            indexed=True,
            signer=self.hab.pre,
            ordinal=None,
            digest=None,
            kind=None,
        )
        headers.extend(ending.signature([signage]))
        client.request(
            method="POST",
            path=path,
            qargs=parse.parse_qs(purl.query),
            headers=headers,
            body=raw,
        )
        self.clients[said] = (client, clientDoer)
