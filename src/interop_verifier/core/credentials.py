"""TEL revocation cue bridge."""

from hio.base import doing
from hio.help import decking
from keri.core import coring


class TeveryCuery(doing.Doer):
    """Moves KERIpy TEL revocation cues into the verifier cue database."""

    def __init__(self, cdb, reger, cues=None, **kwa):
        self.cdb = cdb
        self.reger = reger
        self.cues = cues if cues is not None else decking.Deck()
        super().__init__(**kwa)

    def do(self, tymth, *, tock=0.0, **opts):
        self.wind(tymth)
        self.tock = tock
        yield self.tock
        while True:
            while self.cues:
                cue = self.cues.popleft()
                if cue.get("kin") == "revoked":
                    serder = cue["serder"]
                    said = serder.ked["i"]
                    creder = self.reger.creds.get(said)
                    if creder is not None:
                        self.cdb.snd.pin(keys=(said,), val=coring.Prefixer(qb64=creder.issuer))
                        self.cdb.rev.pin(keys=(said,), val=coring.Dater())
                yield self.tock
            yield self.tock
