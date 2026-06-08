"""Direct-mode parser and escrow processing doer."""

from hio.base import doing
from hio.help import decking


class VerificationAgent(doing.DoDoer):
    """Runs KERIpy parser, KEL/TEL/reply/verifier, and exchange escrows."""

    def __init__(self, hab, parser, kvy, tvy, rvy, verifier, exc, cues=None, **opts):
        self.hab = hab
        self.parser = parser
        self.kvy = kvy
        self.tvy = tvy
        self.rvy = rvy
        self.verifier = verifier
        self.exc = exc
        self.cues = cues if cues is not None else decking.Deck()
        super().__init__(doers=[doing.doify(self.msgDo), doing.doify(self.escrowDo)], **opts)

    def msgDo(self, tymth=None, tock=0.0, **opts):
        self.wind(tymth)
        self.tock = tock
        _ = yield self.tock
        done = yield from self.parser.parsator(local=False)
        return done

    def escrowDo(self, tymth=None, tock=0.0, **opts):
        self.wind(tymth)
        self.tock = tock
        _ = yield self.tock
        while True:
            self.kvy.processEscrows()
            self.rvy.processEscrowReply()
            if self.tvy is not None:
                self.tvy.processEscrows()
            if self.verifier is not None:
                self.verifier.processEscrows()
            self.exc.processEscrow()
            yield
