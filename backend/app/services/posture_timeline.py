def compute_posture_delta(previous, current):
    changes = {}

    for key in current:
        if previous.get(key) != current.get(key):
            changes[key] = {
                "before": previous.get(key),
                "after": current.get(key),
            }

    return changes
