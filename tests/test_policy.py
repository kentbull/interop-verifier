from types import SimpleNamespace

import pytest
from keri import kering

from interop_verifier.core.policy import VerificationPolicy, credential_payload


class CredStore:
    def __init__(self, creds):
        self.creds = creds

    def get(self, keys=None):
        if keys is None:
            return None
        if isinstance(keys, tuple):
            return self.creds.get(keys[0])
        return self.creds.get(keys)


def creder(said, schema="schema-a", issuer="issuer-a", subject="subject-a", edge=None):
    sad = {
        "d": said,
        "i": issuer,
        "s": schema,
        "a": {
            "d": f"{said}-attrs",
            "dt": "2026-01-01T00:00:00.000000+00:00",
            "i": subject,
            "role": said,
        },
    }
    if edge:
        sad["e"] = edge
    return SimpleNamespace(
        said=said,
        schema=schema,
        issuer=issuer,
        sad=sad,
        edge=edge,
    )


def test_policy_allows_unknown_schemas_by_default():
    policy = VerificationPolicy()
    policy.validate(creder("cred-a", schema="unknown"))


def test_policy_can_restrict_schemas_and_issuers():
    policy = VerificationPolicy({
        "allowUnknownSchemas": False,
        "schemas": {"schema-a": {"name": "Example"}},
        "issuers": ["issuer-a"],
    })
    policy.validate(creder("cred-a"))

    with pytest.raises(kering.ValidationError):
        policy.validate(creder("cred-b", schema="schema-b"))

    with pytest.raises(kering.ValidationError):
        policy.validate(creder("cred-c", issuer="issuer-b"))


def test_credential_payload_is_generic_and_includes_chain_summary():
    source = creder("source-a", schema="schema-source", issuer="issuer-source")
    final = creder(
        "final-a",
        edge={"source": {"n": "source-a", "s": "schema-source", "o": "I2I"}},
    )
    reger = SimpleNamespace(creds=CredStore({"source-a": source}))

    payload = credential_payload(
        reger,
        final,
        VerificationPolicy({"schemas": {"schema-a": {"name": "Final"}}}),
    )

    assert payload["type"] == "Final"
    assert payload["credential"] == "final-a"
    assert payload["recipient"] == "subject-a"
    assert payload["attributes"]["role"] == "final-a"
    assert payload["edges"]["source"]["n"] == "source-a"
    assert payload["chain"] == [{
        "label": "source",
        "edge": "source",
        "credential": "source-a",
        "schema": "schema-source",
        "issuer": "issuer-source",
        "operator": "I2I",
    }]
