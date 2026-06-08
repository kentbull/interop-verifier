"""Sally-style cue database for verifier communication state."""

from keri.core import coring, serdering
from keri.db import dbing, subing


class CueBaser(dbing.LMDBer):
    """Stores verifier presentation, revocation, delivery, and ack queues."""

    TailDirPath = "interop-verifier/db"
    AltTailDirPath = ".interop-verifier/db"
    TempPrefix = "interop_verifier_db_"

    def __init__(self, name="cb", headDirPath=None, reopen=True, **kwa):
        self.snd = None
        self.iss = None
        self.rev = None
        self.recv = None
        self.revk = None
        self.ack = None
        super().__init__(name=name, headDirPath=headDirPath, reopen=reopen, **kwa)

    def reopen(self, **kwa):
        super().reopen(**kwa)
        self.snd = subing.CesrSuber(db=self, subkey="snd.", klas=coring.Prefixer)
        self.iss = subing.CesrSuber(db=self, subkey="iss.", klas=coring.Dater)
        self.rev = subing.CesrSuber(db=self, subkey="rev.", klas=coring.Dater)
        self.recv = subing.SerderSuber(db=self, subkey="recv", klas=serdering.SerderACDC)
        self.revk = subing.SerderSuber(db=self, subkey="revk", klas=serdering.SerderACDC)
        self.ack = subing.SerderSuber(db=self, subkey="ack", klas=serdering.SerderACDC)
        return self.env

    def clearEscrows(self):
        self.iss.trim()
        self.rev.trim()
        self.recv.trim()
        self.revk.trim()
        self.ack.trim()

    @staticmethod
    def items(suber, keys=""):
        if hasattr(suber, "getItemIter"):
            return suber.getItemIter(keys=keys)
        return suber.getTopItemIter(keys=keys)

    def getCounts(self):
        return {
            "senders": self.snd.cntAll(),
            "iss": self.iss.cntAll(),
            "rev": self.rev.cntAll(),
            "recv": self.recv.cntAll(),
            "revk": self.revk.cntAll(),
            "ack": self.ack.cntAll(),
        }
