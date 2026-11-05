# python-tapo-local

Client for **TP-Link Tapo cameras** built from reverse engineering the official Tapo
Android app (3.22.304). It talks to the camera on the local network using the same
methods and payloads as the app, and it can optionally use the TP-Link cloud (app API
v2) for push notifications.

It powers the [Tapo Local](https://github.com/hudsonbrendon/ha-tapo-local) Home Assistant integration.

```sh
pip install python-tapo-local
```

## Local

```python
from tapolocal import TapoLocal

cam = TapoLocal("192.168.1.50", "<TP-Link account password>")  # login: admin + cloud password
info = cam.device_info()  # model, firmware, MAC, alias
data = cam.fetch()        # ~44 getters + 24h detection history + today's recordings
cam.call("setLedStatus", {"led": {"config": {"enabled": "off"}}})
```

- Transport comes from [pytapo](https://github.com/JurajNyiri/pytapo) (`securePassthrough`).
  On top of it, this library adds the app's method catalog and request shapes.
- Requests are batched through `multipleRequest`. Methods the firmware doesn't support
  (`-40209`) are skipped.
- Login is attempted **at most twice** per call. Every wrong password counts toward the
  camera's 30‑minute lockout, so `TapoAuthError` is raised and it never loops. A session the
  camera has invalidated (`-40214` on a C200 v3, `-40401`) is replaced by one fresh login and
  the call is repeated. Other camera error codes keep the session.
- Writes use `set<X> {module: {section: {field: value}}}`, the same shape as the matching
  getter. Some C200 quirks: `setDayNightModeConfig` requires `"chn_id": ["1"]`,
  `setFirmwareAutoUpgradeConfig` requires `time` and `random_range`, brightness is only
  accepted through `setImageLumaConfig`, and the siren only takes the legacy
  `{"method": "do", "msg_alarm": {"manual_msg_alarm": …}}` (see `TapoLocal.legacy`).
- `tapolocal.EVENT_TYPES` maps every `alarm_type` from the app's `PlayBackEventType` enum.

## Cloud (optional)

```python
import aiohttp
from tapolocal import TapoCloud, TapoMFARequired

async with aiohttp.ClientSession() as s:
    cloud = TapoCloud(s, "you@example.com", "password")
    try:
        await cloud.login()
    except TapoMFARequired as mfa:
        await cloud.send_mfa_email()
        await cloud.check_mfa(mfa.process_id, input("code: "))
    cameras = await cloud.devices()
    notes = await cloud.notifications(hours=24)
```

- Requests are signed exactly like the app's `m7/r` interceptor:
  `X-Authorization: Timestamp=9999999999, Nonce=…, AccessKey=…, Signature=HMAC-SHA1(...)`.
- `getAppNotificationByPage` only returns data with `direction: "asc"` starting at
  `indexTime`. `getDeviceMsgsByPage` exists in the API, but the app never calls it and it
  always comes back empty.
- TLS is verified against the two TP-Link root CAs that the app itself bundles.

## Development

```sh
uv run --with pytest --with pytest-asyncio --with-editable . pytest
```
