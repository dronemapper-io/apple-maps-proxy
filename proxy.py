"""Apple Maps accessKey fetcher + local tile proxy.

This module:
- Fetches an Apple MapKit `accessKey` using a headless Chromium instance.
- Exposes a small local HTTP proxy (Flask) for calling Apple MapKit tile URLs.

Local usage
-----------
The tile endpoint is compatible with:
  http://localhost:8081/tile?style=7&size=2&scale=1&z={z}&x={x}&y={y}

The server will append:
  &v=<v>&accessKey=<accessKey>

Dependencies
------------
- selenium
- chromedriver-autoinstaller (optional but recommended)
- flask
- urllib3

"""

from __future__ import annotations

import datetime as dt
import json
import os
import time
from typing import Optional
import threading

import urllib3
from urllib.parse import urlencode, unquote, urlparse, parse_qs


# Chromedriver resolution can be invoked from multiple threads (background refresh + request path).
# Cache it process-wide to avoid races and cwd-dependent installs.
_CHROMEDRIVER_LOCK = threading.Lock()
_CHROMEDRIVER_PATH: Optional[str] = None
_CHROMEDRIVER_RESOLVED = False


def _resolve_chromedriver_path() -> Optional[str]:
    """Resolve a usable chromedriver path once per process, safely across threads."""
    global _CHROMEDRIVER_PATH, _CHROMEDRIVER_RESOLVED

    with _CHROMEDRIVER_LOCK:
        if _CHROMEDRIVER_RESOLVED:
            return _CHROMEDRIVER_PATH

        chromedriver = os.environ.get("CHROMEDRIVER")
        if not chromedriver:
            try:
                import chromedriver_autoinstaller

                # Avoid cwd-dependent installs; use the library default install location.
                chromedriver = chromedriver_autoinstaller.install()
            except Exception:
                chromedriver = None

        # Normalize to absolute path when possible (helpful if callers change cwd).
        if chromedriver:
            try:
                chromedriver = os.path.abspath(chromedriver)
            except Exception:
                pass

        _CHROMEDRIVER_PATH = chromedriver
        _CHROMEDRIVER_RESOLVED = True
        return _CHROMEDRIVER_PATH


def _extract_access_key_and_v_from_url(url: str) -> Optional[tuple[str, str]]:
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        access_key = qs.get("accessKey", [None])[0]
        v = qs.get("v", [None])[0]
        if access_key and v:
            return access_key, v
    except Exception:
        pass
    return None


def _extract_access_key_and_v_from_log_message(msg: str) -> Optional[tuple[str, str]]:
    try:
        decoded = json.loads(msg)
        message = decoded.get("message", {})
        params = message.get("params", {})
        for key in ("request", "response"):
            part = params.get(key, {})
            url = part.get("url")
            if isinstance(url, str) and "accessKey=" in url and "v=" in url:
                return _extract_access_key_and_v_from_url(url)
    except Exception:
        pass
    return None


def _getAPIKey(timeout: float = 60) -> tuple[str, str]:
    """Scrape Apple Maps accessKey using a headless Chromium instance.

    Performance-oriented implementation:
    - Uses `pageLoadStrategy=none` to avoid waiting for full page load.
    - Polls performance logs frequently (instead of sleeping 15s).

    Notes
    -----
    Apple Maps accessKey is short-lived. This function is expected to run occasionally, not per-request.
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Selenium is required. Install with: pip install selenium") from e

    chromedriver = _resolve_chromedriver_path()

    options = webdriver.ChromeOptions()
    # Fast, lean headless setup
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Reduce work Chrome does: disable unneeded subsystems and background tasks
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-background-networking")
    options.add_argument("--disable-background-timer-throttling")
    options.add_argument("--disable-renderer-backgrounding")
    options.add_argument("--disable-backgrounding-occluded-windows")
    options.add_argument("--disable-client-side-phishing-detection")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--disable-sync")
    options.add_argument("--metrics-recording-only")
    options.add_argument("--safebrowsing-disable-auto-update")
    options.add_argument("--no-first-run")
    options.add_argument("--mute-audio")

    # Don't download images (we only need network events for accessKey)
    options.add_argument("--blink-settings=imagesEnabled=false")

    # Force direct connections (avoid slow environment/system proxies)
    options.add_argument("--proxy-server=direct://")
    options.add_argument("--proxy-bypass-list=*")

    # Cosmetic/compat
    options.add_argument("--window-size=640,480")

    # Trim feature set further
    options.add_argument("--disable-features=TranslateUI,NetworkQualityEstimator")

    # Keep automation unobtrusive and reduce logging noise
    options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
    options.add_experimental_option("useAutomationExtension", False)

    # Capture DevTools performance logs (Network.*) and don't wait for full load.
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    options.set_capability("pageLoadStrategy", "none")

    # Some sites try to detect automation; this helps reduce that.
    options.add_argument("--disable-blink-features=AutomationControlled")

    try:
        try:
            if chromedriver:
                driver = webdriver.Chrome(service=Service(chromedriver), options=options)
            else:
                driver = webdriver.Chrome(options=options)
        except Exception:
            # If chromedriver auto-install raced or produced a transient/bad path,
            # clear cache and retry resolution once.
            global _CHROMEDRIVER_RESOLVED
            with _CHROMEDRIVER_LOCK:
                _CHROMEDRIVER_RESOLVED = False
            chromedriver = _resolve_chromedriver_path()

            if chromedriver:
                driver = webdriver.Chrome(service=Service(chromedriver), options=options)
            else:
                driver = webdriver.Chrome(options=options)
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "Unable to start Chromium/Chrome driver. Ensure Chrome and chromedriver are installed "
            "and compatible, or set CHROMEDRIVER."
        ) from e

    def _scan_performance_logs(logs: list[dict]) -> Optional[tuple[str, str]]:
        """Extract accessKey and v from Chrome 'performance' log entries.

        Chrome emits multiple event types; handle the most common ones:
        - Network.requestWillBeSent (params.request.url)
        - Network.responseReceived (params.response.url)
        """
        for entry in logs:
            msg = entry.get("message")
            if not msg or "accessKey=" not in msg:
                continue

            pair = _extract_access_key_and_v_from_log_message(msg)
            if pair:
                access_key, v_value = pair
                print(f"Extracted accessKey={access_key} v={v_value}")
                return access_key, v_value

        return None

    try:
        driver.set_page_load_timeout(timeout)
        driver.get("https://maps.apple.com/frame?map=satellite&center=40.69%2C-111.90&span=0.01756288968470443%2C0.06229506710420196")

        deadline = time.time() + timeout
        key_contents: Optional[tuple[str, str]] = None

        # Drain logs continuously: Chrome may only return entries once.
        poll = 0.5
        while key_contents is None and time.time() < deadline:
            try:
                logs = driver.get_log("performance")
            except Exception:
                logs = []

            if logs:
                key_contents = _scan_performance_logs(logs)
                if key_contents:
                    break

            time.sleep(poll)

        if key_contents is None:
            title = ""
            try:
                title = driver.title
            except Exception:
                pass
            raise TimeoutError(
                f"Unable to automatically fetch API key in {timeout}s (page title: {title!r})."
            )

        return key_contents
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def create_app(*, v: Optional[str] = None, access_key: Optional[str] = None, timeout: float = 60):
    """Create the Flask proxy app."""
    from flask import Flask, Response, request

    app = Flask(__name__)

    # Logging: avoid double logs by using app.logger (already configured by Flask) and only
    # adjusting levels/handlers if explicitly requested.
    import logging

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logger = app.logger
    logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
    logger.propagate = False

    logger.info("Fetching initial Apple Maps accessKey...")
    fetched_key, fetched_v = _getAPIKey(timeout=timeout)
    ak = access_key or fetched_key
    current_v = v or fetched_v
    if not current_v:
        raise RuntimeError("Unable to determine v from performance logs.")
    ak_fetched_at = time.time()

    # Concurrency controls / refresh coordination
    ak_lock = threading.Lock()
    ak_refresh_inflight = threading.Condition(ak_lock)
    refreshing = False

    # Refresh policy knobs
    refresh_interval = float(os.environ.get("ACCESS_KEY_REFRESH_INTERVAL_SECONDS", "600"))
    # Cooldown prevents redundant refreshes when the background worker and /tile 401/403 trigger overlap.
    refresh_cooldown = float(os.environ.get("ACCESS_KEY_REFRESH_COOLDOWN_SECONDS", "90"))

    # Track next planned refresh time for /health.
    next_refresh_at = ak_fetched_at + refresh_interval

    stop_event = threading.Event()

    def _maybe_refresh_locked(*, force: bool, reason: str) -> str:
        """Refresh accessKey if needed, with single-flight + cooldown.

        Must be called with ak_lock held.
        """
        nonlocal ak, ak_fetched_at, next_refresh_at, refreshing, current_v

        now = time.time()
        age = now - ak_fetched_at

        # If a refresh is already in progress, wait for it and reuse the result.
        if refreshing:
            # Avoid indefinite wait: if refresh hangs, we still wake periodically.
            end = now + max(5.0, min(30.0, timeout))
            while refreshing and time.time() < end:
                ak_refresh_inflight.wait(timeout=1.0)
            return ak

        # Determine whether we *should* refresh.
        stale = age > refresh_interval
        recently_refreshed = age < refresh_cooldown
        should_refresh = stale or (force and not recently_refreshed)

        if not should_refresh:
            return ak

        refreshing = True
        try:
            logger.info("Refreshing Apple Maps accessKey (force=%s, reason=%s)...", force, reason)
            started = time.time()
            new_key, new_v = _getAPIKey(timeout=timeout)
            ak = new_key
            current_v = new_v or current_v
            ak_fetched_at = time.time()
            next_refresh_at = ak_fetched_at + refresh_interval
            logger.info("accessKey refreshed successfully in %.1fs", ak_fetched_at - started)
            return ak
        finally:
            refreshing = False
            ak_refresh_inflight.notify_all()

    def _get_current_key() -> str:
        with ak_lock:
            return _maybe_refresh_locked(force=False, reason="scheduled")

    def _force_refresh_key(reason: str) -> str:
        with ak_lock:
            return _maybe_refresh_locked(force=True, reason=reason)

    def _get_current_v() -> str:
        with ak_lock:
            return current_v

    def _refresh_worker():
        # Schedule: refresh ~every interval, with jitter to spread load.
        # On failure, exponential backoff up to 5 minutes, then retry.
        import random

        nonlocal next_refresh_at
        backoff = 30.0
        while not stop_event.is_set():
            jitter = random.uniform(30.0, 90.0)
            with ak_lock:
                planned = max(0.0, refresh_interval - (time.time() - ak_fetched_at)) + jitter
                next_refresh_at = time.time() + planned
            logger.debug("Scheduled next accessKey refresh in %.1fs (jitter=%.1fs)", planned, jitter)

            stop_event.wait(planned)
            if stop_event.is_set():
                break

            try:
                with ak_lock:
                    _maybe_refresh_locked(force=True, reason="background")
                backoff = 30.0
            except Exception as e:
                logger.warning("accessKey refresh failed: %s; retrying in %.0fs", e, backoff)
                with ak_lock:
                    next_refresh_at = time.time() + backoff
                stop_event.wait(backoff)
                backoff = min(backoff * 2, 300.0)

        logger.info("accessKey refresher thread exiting")

    refresher = threading.Thread(target=_refresh_worker, name="accessKeyRefresher", daemon=True)
    refresher.start()

    http = urllib3.PoolManager(
        num_pools=16,
        maxsize=64,
        block=True,
        cert_reqs="CERT_REQUIRED",
    )

    req_timeout = urllib3.Timeout(connect=10.0, read=30.0)

    @app.get("/health")
    def health():
        with ak_lock:
            fetched = ak_fetched_at
            next_at = next_refresh_at
        now = time.time()
        age = now - fetched
        payload = {
            "status": "ok",
            "key_age_seconds": int(age),
            "last_refreshed_at": dt.datetime.fromtimestamp(fetched, dt.UTC).isoformat(),
            "next_refresh_eta_seconds": max(0, int(next_at - now)),
            "next_refresh_at": dt.datetime.fromtimestamp(next_at, dt.UTC).isoformat(),
        }
        return payload

    @app.get("/tile")
    def tile():
        q = request.args.to_dict()
        q["v"] = _get_current_v()

        def make_upstream_url(key: str) -> str:
            q["accessKey"] = key
            return f"https://sat-cdn.apple-mapkit.com/tile?{urlencode(q, safe='%')}"

        # Request headers: forward a small safe allowlist.
        headers = {}
        for h in ("Accept", "User-Agent", "Referer", "Origin", "Range"):
            hv = request.headers.get(h)
            if hv:
                headers[h] = hv
        headers["Accept-Encoding"] = "identity"
        headers["Host"] = "sat-cdn.apple-mapkit.com"

        def do_request(upstream_url: str):
            return http.request(
                "GET",
                upstream_url,
                headers=headers,
                preload_content=False,
                redirect=False,
                retries=False,
                timeout=req_timeout,
            )

        r = do_request(make_upstream_url(_get_current_key()))
        if r.status in (401, 403):
            try:
                r.release_conn()
            except Exception:
                pass
            logger.info("Got %s from upstream; refreshing accessKey and retrying once", r.status)
            r = do_request(make_upstream_url(_force_refresh_key(reason=f"upstream_{r.status}")))

        def generate():
            try:
                while True:
                    data = r.read(64 * 1024)
                    if not data:
                        break
                    yield data
            finally:
                try:
                    r.release_conn()
                except Exception:
                    pass

        hop_by_hop = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        }
        resp_headers = []
        for k, vv in r.headers.items():
            lk = k.lower()
            if lk in hop_by_hop or lk == "content-encoding":
                continue
            resp_headers.append((k, vv))

        if not any(k.lower() == "content-type" for k, _ in resp_headers):
            resp_headers.append(("Content-Type", "image/jpeg"))

        headers_dict = {k: vv for k, vv in resp_headers}
        return Response(generate(), status=r.status, headers=headers_dict)

    return app


def serve(host: str = "0.0.0.0", port: int = 8081, *, v: Optional[str] = None, timeout: float = 60) -> None:
    app = create_app(v=v, timeout=timeout)
    app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)


if __name__ == "__main__":
    serve()
