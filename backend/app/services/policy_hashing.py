import json
import hashlib


def canonicalize_json(data):
    if isinstance(data, dict):
        return {k: canonicalize_json(data[k]) for k in sorted(data)}

    elif isinstance(data, list):
        # FIX: ensure list items are comparable (no dict < dict)
        normalized = [canonicalize_json(x) for x in data]

        try:
            return sorted(normalized)
        except TypeError:
            # Fallback: sort by string representation (stable + safe)
            return sorted(normalized, key=lambda x: str(x))

    else:
        return data


def compute_policy_hash(policy_json) -> str:
    canonical = canonicalize_json(policy_json)
    encoded = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
