import base64
import hashlib
import hmac

import pytest

import tapolocal
from tapolocal import api


class FakeTapo:
    """Simula pytapo.Tapo: responde cada método de um multipleRequest."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def performRequest(self, body):
        reqs = body["params"]["requests"]
        self.calls.append([r["method"] for r in reqs])
        out = []
        for r in reqs:
            a = self.answers.get(r["method"], -40209)
            if isinstance(a, Exception):
                raise a
            out.append({"method": r["method"], "error_code": 0, "result": a} if isinstance(a, dict)
                       else {"method": r["method"], "error_code": a, "result": {}})
        return {"result": {"responses": out}}


def local_with(fake):
    loc = tapolocal.TapoLocal("10.0.0.2", "pw")
    loc._tapo = fake
    return loc


def test_batches_and_skips_unsupported():
    fake = FakeTapo({"getDeviceInfo": {"device_info": {"basic_info": {"mac": "AA"}}}})
    data = local_with(fake)._multi(api.LOCAL_QUERIES)
    assert list(data) == ["getDeviceInfo"]  # -40209 fica de fora
    assert all(len(c) <= api.BATCH for c in fake.calls)
    assert sum(map(len, fake.calls)) == len(api.LOCAL_QUERIES)


def test_camera_error_keeps_session_network_error_drops_it():
    loc = local_with(FakeTapo({"getDeviceInfo": Exception('Error: -40214, Response: {"error_code": -40214}')}))
    with pytest.raises(Exception):
        loc._multi_once([api.LOCAL_QUERIES[0]])
    assert loc._tapo is not None  # sem relogin à toa
    loc = local_with(FakeTapo({"getDeviceInfo": ConnectionError("timeout")}))
    with pytest.raises(ConnectionError):
        loc._multi_once([api.LOCAL_QUERIES[0]])
    assert loc._tapo is None


def test_auth_error_retries_once(monkeypatch):
    monkeypatch.setattr(api.time, "sleep", lambda s: None)
    loc = local_with(FakeTapo({"getDeviceInfo": Exception("Invalid authentication data")}))
    created = []

    def client():
        if loc._tapo is None:
            created.append(1)
            loc._tapo = FakeTapo({"getDeviceInfo": Exception("Invalid authentication data")})
        return loc._tapo

    monkeypatch.setattr(loc, "_client", client)
    with pytest.raises(tapolocal.TapoAuthError):
        loc.device_info()
    assert len(created) == 1  # exatamente 1 login novo, nunca um loop


def test_call_raises_on_error_code():
    loc = local_with(FakeTapo({"setLedStatus": -40209}))
    with pytest.raises(tapolocal.TapoCommandError) as err:
        loc.call("setLedStatus", {"led": {"config": {"enabled": "off"}}})
    assert err.value.code == -40209


def test_sign_matches_app_interceptor():
    body, path, nonce = b'{"a":1}', "/api/v2/account/login", "n-1"
    h = tapolocal.sign(body, path, nonce)
    md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
    sig = hmac.new(api.SECRET_KEY.encode(), f"{md5}\n9999999999\n{nonce}\n{path}".encode(), hashlib.sha1).hexdigest()
    assert h["Content-MD5"] == md5
    assert h["X-Authorization"] == f"Timestamp=9999999999, Nonce={nonce}, AccessKey={api.ACCESS_KEY}, Signature={sig}"


async def test_notifications_paginates_ascending(monkeypatch):
    cloud = tapolocal.TapoCloud(None, "u@example.com", "pw", url="https://x")
    pages = [{"notifications": [1, 2], "hasNextPage": True, "currentIndex": 1},
             {"notifications": [3], "hasNextPage": False, "currentIndex": 2}]
    seen = []

    async def fake_call(path, body):
        seen.append((body["direction"], body["index"]))
        return pages[len(seen) - 1]

    monkeypatch.setattr(cloud, "_call", fake_call)
    assert await cloud.notifications() == [1, 2, 3]
    assert seen == [("asc", 0), ("asc", 2)]


def test_ca_bundle_shipped():
    pem = (api.Path(api.__file__).with_name("tplink_cloud_ca.pem")).read_text()
    assert pem.count("BEGIN CERTIFICATE") == 2
