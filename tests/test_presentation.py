"""Verify grant ingestion, signed webhook requests, and revocation payloads."""

import json
from contextlib import ExitStack

from falcon import testing
from keri import kering
from keri.app import habbing, signing
from keri.core import coring, eventing, scheming
from keri.vc import proving, protocoling
from keri.vdr import credentialing

from interop_verifier.core import serving
from interop_verifier.core.policy import VerificationPolicy, credential_payload, revocation_payload


def test_v1_grant_ingestion_and_health(tmp_path):
    """Real v1 evidence reaches admission, serialized HTTP requests, and revocation cues."""
    version = kering.Vrsn_1_0
    modern = kering.Version.major >= 2
    protocol = {"version": version} if modern else {}
    genus = {"gvrsn": version} if modern else {}
    with ExitStack() as stack:
        issuer, ihab = stack.enter_context(habbing.openHab(name="issuer", temp=True, **protocol))
        verifier, vhab = stack.enter_context(habbing.openHab(name="verifier", temp=True, **protocol))
        rgy = credentialing.Regery(hby=issuer, name="issuer", temp=True)
        stack.callback(rgy.reger.close, clear=True)
        doers = serving.setup(verifier, vhab, alias="verifier", httpPort=0,
                              hook="http://127.0.0.1:1/", policy=VerificationPolicy({"issuers": [ihab.pre]}),
                              headDirPath=str(tmp_path))
        server, comms, tel_cues, handler, agent = doers
        stack.callback(server.server.close)
        stack.callback(comms.cdb.close, clear=True)
        stack.callback(comms.reger.close, clear=True)
        stack.callback(handler.notifier.noter.close, clear=True)
        ingress = server.server.app._router.find("/")[0]
        stack.callback(ingress.mbx.close, clear=True)
        client = testing.TestClient(server.server.app)
        assert getattr(agent.parser, "version", version) == version

        # Anchor registry and issuance before disclosing their real serialized proofs.
        registry = rgy.makeRegistry(name="registry", prefix=ihab.pre, **protocol)
        vcp = registry.vcp
        ihab.interact(data=[eventing.SealEvent(vcp.pre, vcp.snh, vcp.said)._asdict()], **protocol)
        registry.anchorMsg(pre=vcp.pre, regd=vcp.said, seqner=coring.Seqner(sn=ihab.kever.sn),
                           saider=coring.Saider(qb64=ihab.kever.serder.said))
        rgy.processEscrows()
        schema = scheming.Schemer(sed={"$id": "", "$schema": "http://json-schema.org/draft-07/schema#",
                                      "type": "object"})
        verifier.db.schema.pin(keys=schema.said, val=schema)
        creder = proving.credential(issuer=ihab.pre, recipient=vhab.pre, schema=schema.said,
                                    status=registry.regk, data={}, **protocol)
        issuance = registry.issue(said=creder.said)
        anchor = ihab.interact(data=[eventing.SealEvent(issuance.pre, issuance.snh, issuance.said)._asdict()],
                               **protocol)
        registry.anchorMsg(pre=issuance.pre, regd=issuance.said, seqner=coring.Seqner(sn=ihab.kever.sn),
                           saider=coring.Saider(qb64=ihab.kever.serder.said))
        rgy.processEscrows()
        seal = (coring.Prefixer(qb64=issuance.pre), coring.Seqner(sn=issuance.sn),
                coring.Saider(qb64=issuance.said))
        if modern:
            # Main exposes explicit genus on the core serializer; released signing is fixed v1.
            from keri.core import messagize
            acdc = bytes(messagize(creder, bonds=[eventing.SealEvent(*seal)], framed=True, **genus))
        else:
            acdc = signing.serialize(creder, *seal)
        issuance_wire = b"".join(rgy.reger.clonePreIter(pre=creder.said, **genus))
        grant, attachments = protocoling.ipexGrantExn(hab=ihab, recp=vhab.pre, message="",
                                                     acdc=acdc, iss=issuance_wire, anc=anchor, **protocol)
        support = bytearray(ihab.replay(**genus))
        support.extend(b"".join(rgy.reger.clonePreIter(pre=registry.regk, **genus)))
        response = client.simulate_put("/", body=bytes(support) + grant.raw + attachments)
        assert response.status_code == 204
        agent.parser.parse(ims=agent.parser.ims)
        assert verifier.db.exns.get(keys=(grant.said,)) is not None
        handler.processNotes()
        agent.verifier.processEscrows()
        assert comms.reger.saved.get(keys=(creder.said,)) is not None
        assert comms.reger.creds.get(keys=(creder.said,)).raw == creder.raw
        comms.processPresentations()
        assert [saved.said for _, saved in comms.cdb.items(comms.cdb.recv)] == [creder.said]
        health = client.simulate_get("/health")
        assert health.status_code == 200
        assert health.json["counts"]["recv"] == 1
        assert health.json["stats"]["savedCredentials"] == 1

        # Give the real HTTP doer its scheduler clock before it opens its request queue.
        comms.wind(tymth=lambda: 0.0)
        stack.callback(comms.exit)
        comms.processReceived(db=comms.cdb.recv, action="iss")
        outgoing, _ = comms.clients[creder.said]
        stack.callback(outgoing.close)
        request, = outgoing.requests
        payload = json.loads(request["body"])
        assert request["method"] == "POST"
        assert request["headers"]["Sally-Resource"] == schema.said
        assert request["headers"]["Signature-Input"]
        assert request["headers"]["Signature"]
        assert payload["action"] == "iss"
        assert payload["actor"] == ihab.pre
        assert payload["data"]["issuer"] == ihab.pre
        assert payload["data"]["schema"] == schema.said
        assert payload["data"]["recipient"] == vhab.pre
        # A stored source is a real Serder too; its chain summary must stay JSON-native.
        chained = proving.credential(issuer=ihab.pre, recipient=vhab.pre, schema=schema.said,
                                     status=registry.regk, data={},
                                     source={"source": {"n": creder.said, "s": schema.said, "o": "I2I"}},
                                     **protocol)
        summary = json.loads(json.dumps(credential_payload(comms.reger, chained, comms.policy)))
        assert summary["chain"][0]["issuer"] == ihab.pre
        assert summary["chain"][0]["schema"] == schema.said

        # Admit a real revocation and read its TEL timestamp for the callback payload.
        revocation = registry.revoke(said=creder.said)
        ihab.interact(data=[eventing.SealEvent(revocation.pre, revocation.snh, revocation.said)._asdict()],
                      **protocol)
        registry.anchorMsg(pre=revocation.pre, regd=revocation.said,
                           seqner=coring.Seqner(sn=ihab.kever.sn),
                           saider=coring.Saider(qb64=ihab.kever.serder.said))
        rgy.processEscrows()
        replay = bytearray(ihab.replay(**genus))
        replay.extend(b"".join(rgy.reger.clonePreIter(pre=creder.said, **genus)))
        agent.parser.parse(ims=replay)
        state = comms.reger.tevers[registry.regk].vcState(creder.said)
        assert state.et == kering.Ilks.rev
        task = tel_cues.do(tymth=lambda: 0.0)
        next(task)
        while tel_cues.cues:
            next(task)
        task.close()
        assert comms.cdb.snd.get(keys=(creder.said,)).qb64 == ihab.pre
        comms.processRevocations()
        assert [saved.said for _, saved in comms.cdb.items(comms.cdb.revk)] == [creder.said]
        payload = json.loads(json.dumps(revocation_payload(comms.reger, creder, comms.policy)))
        assert payload["issuer"] == ihab.pre
        assert payload["revocationTimestamp"] == state.dt
