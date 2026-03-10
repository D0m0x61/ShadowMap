import time


class RateLimiter:
    def __init__(self, delay: float):
        self.delay = delay
        self._last_call: float = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_call = time.monotonic()

    def reset(self) -> None:
        self._last_call = 0.0
