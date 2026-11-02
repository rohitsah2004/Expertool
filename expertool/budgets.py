"""Shared broker-process limits. Cross-process durable queueing belongs to milestone 5."""
import threading
import time
from contextlib import contextmanager


class SharedLimits:
    def __init__(self):
        self.condition = threading.Condition()
        self.active = 0
        self.active_limits = []
        self.targets = {}
        self.next_request = {}
        self.counts = {}

    @contextmanager
    def acquire(self, namespace, host, config, egress, run_id=None):
        key = (namespace, host)
        run = (namespace, run_id)
        deadline = time.monotonic() + config['timeout']
        with self.condition:
            while True:
                if run_id is not None and self.counts.get(run, 0) >= config['max_requests']:
                    raise ValueError('Shared run request budget exhausted')
                delay = self.next_request.get(key, 0) - time.monotonic()
                ceiling=min([egress['global_concurrency'],*self.active_limits])
                if self.active < ceiling and self.targets.get(key, 0) < egress['target_concurrency'] and delay <= 0:
                    self.active += 1
                    self.active_limits.append(egress['global_concurrency'])
                    self.targets[key] = self.targets.get(key, 0) + 1
                    self.next_request[key] = time.monotonic() + 1/config['rate_per_second']
                    if run_id is not None:
                        self.counts[run] = self.counts.get(run, 0) + 1
                    break
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Shared concurrency/rate wait exceeded timeout')
                self.condition.wait(min(remaining, max(.01, delay) if delay > 0 else .1))
        try:
            yield
        finally:
            with self.condition:
                self.active -= 1
                self.active_limits.remove(egress['global_concurrency'])
                self.targets[key] -= 1
                self.condition.notify_all()


LIMITS = SharedLimits()
