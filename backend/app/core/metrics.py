import threading
from app.utils.datetime import utc_now

_lock = threading.Lock()

_metrics = {
    "started_at": utc_now(),
    "remediations_executed": 0,
    "remediations_failed": 0,
    "drift_detected": 0,
    "fleet_divergence": 0,
    "auto_repairs_triggered": 0,
    "scheduler_failures": 0,
    "queue_drop_count": 0,
}


def increment(metric_name: str, amount: int = 1):
    with _lock:
        if metric_name in _metrics:
            _metrics[metric_name] += amount


def get_metrics():
    with _lock:
        return dict(_metrics)
