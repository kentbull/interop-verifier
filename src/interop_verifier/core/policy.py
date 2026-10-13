"""Generic credential policy and webhook payload helpers."""

from keri import kering


class VerificationPolicy:
    """Schema-agnostic verifier policy with optional config restrictions."""

    def __init__(self, config=None):
        config = config or {}
        schemas = config.get("schemas") or {}
        if isinstance(schemas, list):
            schemas = {said: {"name": said} for said in schemas}
        self.schemas = schemas
        self.allow_unknown_schemas = bool(config.get("allowUnknownSchemas", True))
        self.issuers = set(config.get("issuers") or [])

    def validate(self, creder):
        if self.schemas and creder.schema not in self.schemas and not self.allow_unknown_schemas:
            raise kering.ValidationError(f"unsupported credential schema {creder.schema}")
        if self.issuers and creder.issuer not in self.issuers:
            raise kering.ValidationError(f"credential issuer {creder.issuer} is not allowed")

    def schema_name(self, schema):
        entry = self.schemas.get(schema)
        if isinstance(entry, dict):
            return entry.get("name") or schema
        if isinstance(entry, str):
            return entry
        return schema


def credential_payload(reger, creder, policy):
    attrs = dict(creder.sad.get("a") or {})
    edges = creder.edge or creder.sad.get("e") or {}
    data = {
        "type": policy.schema_name(creder.schema),
        "schema": creder.schema,
        "issuer": creder.issuer,
        "issueTimestamp": attrs.get("dt"),
        "credential": creder.said,
        "recipient": attrs.get("i"),
        "attributes": attrs,
        "edges": edges,
        "rules": creder.sad.get("r"),
        "chain": chain_summary(reger, creder),
    }
    return {key: value for key, value in data.items() if value is not None}


def revocation_payload(reger, creder, policy):
    state = reger.tevers[creder.sad["ri"]].vcState(creder.said)
    return {
        "type": policy.schema_name(creder.schema),
        "schema": creder.schema,
        "credential": creder.said,
        "issuer": creder.issuer,
        "revocationTimestamp": state.dt if state is not None else None,
    }


def chain_summary(reger, creder):
    seen = set()
    out = []

    def visit(current, label=None):
        edges = current.edge or current.sad.get("e") or {}
        if not isinstance(edges, dict):
            return
        for edge_label, edge in edges.items():
            if not isinstance(edge, dict):
                continue
            said = edge.get("n")
            if not said or said in seen:
                continue
            seen.add(said)
            source = credential_by_said(reger, said)
            out.append({
                "label": label or edge_label,
                "edge": edge_label,
                "credential": said,
                "schema": source.schema if source is not None else edge.get("s"),
                "issuer": source.issuer if source is not None else None,
                "operator": edge.get("o"),
            })
            if source is not None:
                visit(source, edge_label)

    visit(creder)
    return out


def credential_by_said(reger, said):
    try:
        return reger.creds.get(keys=(said,))
    except TypeError:
        return reger.creds.get(said)
