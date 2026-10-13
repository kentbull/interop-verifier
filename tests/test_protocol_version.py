"""Real signed OOBIs preserve one selected protocol and attachment genus."""

import falcon
from falcon import testing
import pytest

from keri import kering
from keri.app import habbing
from keri.core import parsing

from interop_verifier.app.cli import init_habery
from interop_verifier.core import serving


@pytest.mark.parametrize("version", [None, kering.Vrsn_1_0, kering.Vrsn_2_0],
                         ids=["default", "v1", "v2"])
def test_signed_oobi_after_reopen(tmp_path, version):
    """A fresh peer verifies replay, location, and end-role after issuer reopen."""
    selected = version or kering.Version
    options = dict(name="verifier", base="", bran=None, config_file=None,
                   config_dir=None, salt=None, head_dir_path=str(tmp_path), version=version)
    if kering.Version.major < 2 and version == kering.Vrsn_2_0:
        # Released KERIpy has only a v1 parser; explicit v2 must fail before opening storage.
        with pytest.raises(ValueError, match="version-aware KERIpy"):
            init_habery(**options)
        return
    hby = init_habery(**options)
    try:
        hab = serving.incept_if_new(hby, "verifier", {})
        aid = hab.pre
        actual = hab.kever.serder.pvrsn if kering.Version.major >= 2 else hab.kever.serder.version
        assert actual == selected
    finally:
        hby.close()

    hby = init_habery(**options)
    try:
        hab = serving.incept_if_new(hby, "verifier", {})
        assert hab.pre == aid
        assert getattr(hby.psr, "version", kering.Vrsn_1_0) == selected
        app = falcon.App()
        app.add_route("/oobi/{aid}/controller", serving.VerifierOOBIEnd(hby, hab, 9723))
        response = testing.TestClient(app).simulate_get(f"/oobi/{aid}/controller")
        assert response.status_code == 200
        # Decompose independently before processing into a peer with no prior state.
        kwa = {"version": selected} if kering.Version.major >= 2 else {}
        if kwa:
            frames = parsing.Parser(**kwa).parse(ims=bytearray(response.content), processive=False)
            assert len(frames) == 3
            assert [frame.serder.pvrsn for frame in frames] == [selected] * 3
            assert [frame.serder.ked["t"] for frame in frames] == ["icp", "rpy", "rpy"]
        with habbing.openHby(name="peer", temp=True, **kwa) as peer:
            peer.psr.parse(ims=bytearray(response.content))
            assert peer.kevers[aid].serder.said == hab.kever.serder.said
            assert peer.db.locs.get(keys=(aid, "http")).url == "http://127.0.0.1:9723"
            assert peer.db.ends.get(keys=(aid, kering.Roles.controller, aid)).allowed
    finally:
        hby.close()
