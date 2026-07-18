def vulnerable(payload=None):
    """Minimal target for dynamic harness real-call E2E."""
    if payload is None:
        payload = {}
    marker = payload.get("marker", "ORACLE_HIT")
    print(marker)
    return marker
