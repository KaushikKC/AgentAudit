"""Dashboard tests -- data layer directly, plus one live HTTP round-trip."""

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from agentaudit.dashboard.data import DashboardData
from agentaudit.dashboard.server import make_handler, seed_demo
from agentaudit.storage import SQLiteStore


@pytest.fixture()
def data():
    store = SQLiteStore(":memory:", check_same_thread=False)
    seed_demo(store)
    return DashboardData(store)


def test_seed_creates_sessions(data):
    sessions = data.sessions()
    agents = {s["agent_id"] for s in sessions}
    assert {"kyc-checker-v3", "support-triage-v2"} <= agents


def test_session_verifies_and_hides_pii(data):
    sid = next(s["session_id"] for s in data.sessions() if s["agent_id"] == "kyc-checker-v3")
    detail = data.session(sid)
    assert detail["verification"]["ok"]
    assert detail["verification"]["failed"] == 0
    assert "Jane" not in json.dumps(detail)          # redacted input never surfaces
    assert detail["anchor"]["backend"] == "witness"  # anchored session


def test_session_reports_control_coverage(data):
    sid = next(s["session_id"] for s in data.sessions() if s["agent_id"] == "kyc-checker-v3")
    frameworks = {c["framework"] for c in data.session(sid)["controls"]}
    assert "EU AI Act" in frameworks


def test_simulate_tamper_is_detected_and_nondestructive(data):
    sid = data.sessions()[0]["session_id"]
    t = data.simulate_tamper(sid, 0)
    assert t["verification"]["ok"] is False
    assert t["verification"]["failed"] >= 1
    # The real stored session still verifies -- tamper was in-memory only.
    assert data.session(sid)["verification"]["ok"]


def test_live_server_round_trip(data):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(data))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        base = f"http://127.0.0.1:{port}"
        html = urllib.request.urlopen(base + "/", timeout=5).read().decode()
        assert "<title>AgentAudit" in html

        sessions = json.loads(urllib.request.urlopen(base + "/api/sessions", timeout=5).read())
        assert sessions
        sid = sessions[0]["session_id"]
        det = json.loads(urllib.request.urlopen(f"{base}/api/session?id={sid}", timeout=5).read())
        assert det["verification"]["ok"]

        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(base + "/api/session", timeout=5)  # missing id
        assert e.value.code == 400
    finally:
        httpd.shutdown()
        httpd.server_close()
