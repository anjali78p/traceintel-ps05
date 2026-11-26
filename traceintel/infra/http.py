from __future__ import annotations
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

UA = "TRACEINTEL-hackathon/0.1 (passive public-data lookups; contact: project owner)"


@dataclass
class HttpResponse:
    status: int
    body: str


class UrllibHttp:
    """Live HTTP client (stdlib only). Talks to public data services (RDAP, DoH, crt.sh), never to the suspect host."""

    def __init__(self, timeout=10, min_interval=1.0):
        self.timeout, self.min_interval, self._last = timeout, min_interval, {}

    def get(self, url, headers=None, timeout=None) -> HttpResponse:
        host = urlparse(url).netloc
        wait = self.min_interval - (time.monotonic() - self._last.get(host, 0))
        if wait > 0:
            time.sleep(wait)
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                return HttpResponse(r.status, r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return HttpResponse(e.code, "")
        finally:
            self._last[host] = time.monotonic()
