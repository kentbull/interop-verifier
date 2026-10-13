"""KERIpy/Hio service setup for the generalized verifier."""

import json
import os
from importlib import resources

import falcon
from hio.base import doing
from hio.core import http
from hio.help import decking
from keri.app import habbing, indirecting, notifying, oobiing, storing
from keri.app.habbing import Hab, Habery
from keri import kering
from keri.core import eventing, parsing, routing, scheming
from keri.end import ending
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import verifying
from keri.vdr.eventing import Tevery
try:
    from keri.vdr.eventing import Reger
except ImportError:
    from keri.vdr.viring import Reger

from interop_verifier.core import basing, handling, httping, monitoring
from interop_verifier.core.credentials import TeveryCuery
from interop_verifier.core.policy import VerificationPolicy
from interop_verifier.core.verifying import VerificationAgent


def incept_if_new(hby: Habery, alias: str, incept_args: dict):
    hab = hby.habByName(name=alias)
    if hab is not None:
        return hab
    kwa = {"version": hby.version} if hasattr(hby, "version") else {}
    return hby.makeHab(name=alias, **kwa, **inception_config(**incept_args))


def run_doers(doers, expire=0.0):
    doist = doing.Doist(limit=expire, tock=0.03125, real=True)
    doist.do(doers=doers)


def load_schemas(hby: Habery, paths):
    for path in paths or []:
        with open(path, "rb") as fp:
            schemer = scheming.Schemer(raw=fp.read())
        hby.db.schema.pin(keys=(schemer.said,), val=schemer)


def setupDoers(
    hby: Habery,
    hab: Hab,
    alias: str,
    http_port: int,
    hook: str,
    policy: VerificationPolicy,
    timeout: int = 10,
    retry: int = 3,
    clear_escrows: bool = True,
    head_dir_path: str | None = None,
):
    hbyDoer = habbing.HaberyDoer(habery=hby)
    obl = oobiing.Oobiery(hby=hby)
    doers = [hbyDoer, *obl.doers]
    doers += setup(
        hby,
        hab,
        alias=alias,
        httpPort=http_port,
        hook=hook,
        policy=policy,
        timeout=timeout,
        retry=retry,
        clear_escrows=clear_escrows,
        headDirPath=head_dir_path,
    )
    return doers


def setup(
    hby: Habery,
    hab: Hab,
    alias: str,
    httpPort: int,
    hook: str,
    policy,
    timeout=10,
    retry=3,
    clear_escrows=True,
    headDirPath=None,
):
    cues = decking.Deck()
    if hab is None:
        raise ValueError(f"Identifier with alias '{alias}' does not exist")

    app = falcon.App(middleware=httping.cors_middleware())
    server = http.Server(port=httpPort, app=app)
    httpServerDoer = http.ServerDoer(server=server)

    reger = Reger(name=hab.name, db=hab.db, temp=False, headDirPath=headDirPath)
    verifier = verifying.Verifier(hby=hby, reger=reger)
    mbx = storing.Mailboxer(name=hby.name, headDirPath=headDirPath)
    exc = exchanging.Exchanger(hby=hby, handlers=[])
    rvy = routing.Revery(db=hby.db)
    notifier = notifying.Notifier(hby=hby)
    protocoling.loadHandlers(hby=hby, exc=exc, notifier=notifier)

    kvy = eventing.Kevery(db=hby.db, lax=True, local=False, rvy=rvy)
    kvy.registerReplyRoutes(router=rvy.rtr)
    tvy = Tevery(reger=verifier.reger, db=hby.db, local=False)
    tvy.registerReplyRoutes(router=rvy.rtr)

    cdb = basing.CueBaser(name=hby.name, headDirPath=headDirPath)
    if clear_escrows:
        cdb.clearEscrows()
    tc = TeveryCuery(cdb=cdb, reger=reger, cues=tvy.cues)
    kwa = {"version": hby.version} if hasattr(hby, "version") else {}
    parser = parsing.Parser(framed=True, kvy=kvy, tvy=tvy, rvy=rvy, vry=verifier, exc=exc, **kwa)
    comms = handling.Communicator(
        hby=hby,
        hab=hab,
        cdb=cdb,
        reger=reger,
        hook=hook,
        policy=policy,
        timeout=timeout,
        retry=retry,
    )

    httpEnd = CountingHttpEnd(rxbs=parser.ims, mbx=mbx)
    app.add_route(
        "/health",
        monitoring.HealthEnd(
            cdb=cdb,
            hab=hab,
            stats=lambda: verifier_stats(
                parser=parser,
                ingress=httpEnd,
                hby=hby,
                reger=reger,
                notifier=notifier,
            ),
        ),
    )
    load_verifier_ends(app, hby=hby, hab=hab, httpPort=httpPort)
    app.add_route("/", httpEnd)
    agent = VerificationAgent(hab=hab, parser=parser, kvy=kvy, tvy=tvy, rvy=rvy, verifier=verifier, exc=exc, cues=cues)
    return [
        httpServerDoer,
        comms,
        tc,
        *handling.loadHandlers(cdb=cdb, hby=hby, notifier=notifier, parser=parser),
        agent,
    ]


def load_verifier_ends(app, hby: Habery, hab: Hab, httpPort: int):
    app.add_route('/end/{aid}/{role}', ending.PointEnd(hby=hby))
    app.add_route('/loc', ending.LocationEnd(hby=hby))
    app.add_route('/admin', ending.AdminEnd(hby=hby))

    end = VerifierOOBIEnd(hby=hby, hab=hab, httpPort=httpPort)
    app.add_route("/oobi", end)
    app.add_route("/oobi/{aid}", end)
    app.add_route("/oobi/{aid}/{role}", end)
    app.add_route("/oobi/{aid}/{role}/{eid}", end)


class VerifierOOBIEnd(ending.OOBIEnd):
    def __init__(self, hby: Habery, hab: Hab, httpPort: int):
        super().__init__(hby=hby, default=hab.pre)
        self.hab = hab
        self.httpPort = httpPort

    def on_get(self, req, rep, aid=None, role=None, eid=None):
        aid = aid if aid is not None else self.default
        if aid == self.hab.pre and (role is None or role == kering.Roles.controller) and (eid is None or eid == self.hab.pre):
            if aid not in self.hby.kevers:
                rep.status = falcon.HTTP_NOT_FOUND
                return

            kever = self.hby.kevers[aid]
            if not self.hby.db.fullyWitnessed(kever.serder):
                rep.status = falcon.HTTP_NOT_FOUND
                return

            url = f"http://127.0.0.1:{self.httpPort}"
            msgs = bytearray()
            # Replay attachments and signed replies share the ingress genus.
            version = getattr(self.hby, "version", None)
            replay_kwa = {"gvrsn": version} if version else {}
            reply_kwa = {"version": version, "gvrsn": version} if version else {}
            msgs.extend(self.hab.replay(aid, **replay_kwa))
            msgs.extend(self.hab.makeLocScheme(eid=self.hab.pre, scheme="http", url=url,
                                               **reply_kwa))
            msgs.extend(self.hab.makeEndRole(self.hab.pre, kering.Roles.controller, True,
                                             **reply_kwa))

            rep.status = falcon.HTTP_200
            rep.set_header(ending.OOBI_AID_HEADER, aid)
            rep.content_type = "application/cesr"
            rep.data = bytes(msgs)
            return

        return super().on_get(req, rep, aid=aid, role=role, eid=eid)


class CountingHttpEnd(indirecting.HttpEnd):
    def __init__(self, *args, **kwargs):
        self.posts = 0
        self.puts = 0
        self.lastPutSize = 0
        self.lastPostSize = 0
        super().__init__(*args, **kwargs)

    def on_post(self, req, rep):
        self.posts += 1
        self.lastPostSize = int(req.get_header("Content-Length", required=False) or 0)
        return super().on_post(req, rep)

    def on_put(self, req, rep):
        self.puts += 1
        body = req.bounded_stream.read()
        self.lastPutSize = len(body)
        self.rxbs.extend(body)

        rep.status = falcon.HTTP_204


def count_suber(suber):
    if suber is None:
        return 0
    if hasattr(suber, "cntAll"):
        return suber.cntAll()
    if hasattr(suber, "getItemIter"):
        return len(list(suber.getItemIter()))
    return len(list(suber.getTopItemIter()))


def verifier_stats(parser, ingress, hby, reger, notifier):
    return {
        "httpPosts": ingress.posts,
        "httpPuts": ingress.puts,
        "lastPostSize": ingress.lastPostSize,
        "lastPutSize": ingress.lastPutSize,
        "parserBacklog": len(parser.ims),
        "exns": count_suber(hby.db.exns),
        "exnEscrows": count_suber(hby.db.epse),
        "notices": count_suber(notifier.noter.notes),
        "savedCredentials": count_suber(reger.saved),
        "missingSchemaEscrows": count_suber(reger.mse),
        "missingRegistryEscrows": count_suber(reger.mre),
        "missingChainEscrows": count_suber(reger.mce),
    }


def inception_config(name=None, base=None, alias=None, bran=None, incept_file=None, config_dir=None):
    if incept_file is None:
        raw = resources.files("interop_verifier.data").joinpath("interop-verifier-incept-no-wits.json").read_text()
        config = json.loads(raw)
    else:
        path = incept_file if config_dir is None else os.path.join(config_dir, incept_file)
        with open(path, "r", encoding="utf-8") as fp:
            config = json.load(fp)
    return {
        "transferable": config.get("transferable", True),
        "wits": config.get("wits", []),
        "toad": config.get("toad", 0),
        "icount": config.get("icount", 1),
        "ncount": config.get("ncount", 1),
        "isith": config.get("isith", "1"),
        "nsith": config.get("nsith", "1"),
        "delpre": config.get("delpre"),
        "estOnly": config.get("estOnly", config.get("est_only", False)),
        "data": config.get("data"),
    }
