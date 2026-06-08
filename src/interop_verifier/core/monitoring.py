"""Health endpoint."""

import falcon
from keri.help import nowIso8601

import interop_verifier


class HealthEnd:
    def __init__(self, cdb=None, hab=None, stats=None):
        self.cdb = cdb
        self.hab = hab
        self.stats = stats

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_OK
        resp.media = {
            "message": f"Health is okay. Time is {nowIso8601()}",
            "version": interop_verifier.__version__,
            "pre": self.hab.pre if self.hab else None,
            "counts": self.cdb.getCounts() if self.cdb else {},
            "stats": self.stats() if self.stats else {},
        }
