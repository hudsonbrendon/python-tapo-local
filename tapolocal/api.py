"""Tapo camera clients: local (via pytapo transport) and TP-Link cloud (app API v2).

Tudo aqui saiu da engenharia reversa do app Tapo 3.22.304 (com.tplink.iot):
- métodos/módulos/seções locais: libtapocameranetwork/model/{Method,Module,Section}
- nuvem: com/tplink/cloud/api/*V2Api + interceptors m7/r (assinatura) e m7/q (query)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import ssl
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import aiohttp

# ---------------------------------------------------------------- local

# (método, params) — mesmos formatos que o app monta em mv0/zk.java.
# Câmeras que não suportam um método respondem -40209 e ele só fica de fora.
LOCAL_QUERIES: list[tuple[str, dict]] = [
    ("getDeviceInfo", {"device_info": {"name": ["basic_info"]}}),
    ("getClockStatus", {"system": {"name": ["clock_status"]}}),
    ("getTimezone", {"system": {"name": ["basic"]}}),
    ("getLastAlarmInfo", {"system": {"name": ["last_alarm_info"]}}),
    ("getUserID", {"system": {"get_user_id": {}}}),
    ("getConnectionType", {"network": {"get_connection_type": {}}}),
    ("getDeviceIpAddress", {"network": {"name": ["wan"]}}),
    ("getVideoQualities", {"video": {"name": ["main"]}}),
    ("getVideoCapability", {"video_capability": {"name": ["main", "minor"]}}),
    ("getAudioConfig", {"audio_config": {"name": ["speaker", "microphone", "record_audio"]}}),
    ("getRecordPlan", {"record_plan": {"name": ["chn1_channel"]}}),
    ("getCircularRecordingConfig", {"harddisk_manage": {"name": ["harddisk"]}}),
    ("getSdCardStatus", {"harddisk_manage": {"table": ["hd_info"]}}),
    ("getFirmwareUpdateStatus", {"cloud_config": {"name": ["upgrade_status"]}}),
    ("getFirmwareAutoUpgradeConfig", {"auto_upgrade": {"name": ["common"]}}),
    ("getCloudConfig", {"cloud_config": {"name": ["upgrade_info"]}}),
    ("getMsgPushEventList", {"msg_push": {"table": ["msg_push_event"]}}),
    ("getAlertEventType", {"msg_alarm": {"table": ["msg_alarm_type"]}}),
    ("getDetectionConfig", {"motion_detection": {"name": ["motion_det"]}}),
    ("getPersonDetectionConfig", {"people_detection": {"name": ["detection"]}}),
    ("getUpnpInfo", {"upnpc": {"name": ["upnpc_info"]}}),
    ("getOnvifSecurityConfig", {"security_config": {"onvif_security_config": {}}}),
    ("getThirdPartyCompatibility", {"local_ctrl": {"name": ["third_party_setting"]}}),
    ("getTapoCareServiceList", {"tapo_care": {"name": ["service_list"]}}),
    ("getLensMaskConfig", {"lens_mask": {"name": ["lens_mask_info"]}}),
    ("getLedStatus", {"led": {"name": ["config"]}}),
    ("getRotationStatus", {"image": {"name": ["switch"]}}),
    ("getDayNightModeConfig", {"image": {"name": ["common"]}}),
    ("getTargetTrackConfig", {"target_track": {"name": ["target_track_info"]}}),
    ("getSmartTrackConfig", {"smart_track": {"name": ["smart_track_info"]}}),
    ("getSmartTrackCapability", {"smart_track": {"name": ["smart_track_capability"]}}),
    ("getMsgPushConfig", {"msg_push": {"name": ["chn1_msg_push_info"]}}),
    ("getAlertConfig", {"msg_alarm": {"name": ["chn1_msg_alarm_info"]}}),
    ("getAlertTypeList", {"msg_alarm": {"name": ["alert_type"]}}),
    ("getTamperDetectionConfig", {"tamper_detection": {"name": ["tamper_det"]}}),
    ("getBCDConfig", {"sound_detection": {"name": ["bcd"]}}),
    ("getVehicleDetectionConfig", {"vehicle_detection": {"name": ["detection"]}}),
    ("getPetDetectionConfig", {"pet_detection": {"name": ["detection"]}}),
    ("getCoverConfig", {"cover": {"name": ["cover"]}}),
    ("getOsd", {"OSD": {"name": ["date"]}}),
    ("getPresetConfig", {"preset": {"name": ["preset"]}}),
    ("getPatrolStatus", {"patrol": {"get_patrol_status": {}}}),
    ("getNightVisionCapability", {"image_capability": {"name": ["supplement_lamp"]}}),
]
# Polling rápido (5 s) para movimento/pessoa "ao vivo"; o tapo_control usa ONVIF pra isso.
LIVE_QUERY = ("getLastAlarmInfo", {"system": {"name": ["last_alarm_info"]}})
BATCH = 12  # o firmware aceita lotes desse tamanho sem reclamar (testado na C200)


class TapoAuthError(Exception):
    """Senha errada ou câmera em suspensão temporária (lockout de 30 min)."""


class TapoCommandError(Exception):
    def __init__(self, method: str, code) -> None:
        super().__init__(f"{method} falhou: {code}")
        self.code = code


class TapoLocal:
    """Lê a câmera pelo mesmo protocolo do app, via transporte do pytapo.

    Login = usuário `admin` + senha da conta TP-Link (igual ao app/tapo_control).
    No máximo 1 nova tentativa de login: cada senha errada conta pro lockout
    de 30 min da câmera, mas a C200 fw 1.9.1 às vezes recusa um login logo
    depois de outro (ex.: tapo_control entrando no mesmo segundo).
    """

    def __init__(self, host: str, password: str) -> None:
        self.host = host
        self._password = password
        self._tapo = None
        self._user_id: int | None = None
        self._lock = threading.Lock()  # pytapo guarda seq/nonce; 1 requisição por vez

    def _client(self):
        if self._tapo is None:
            from pytapo import Tapo  # import tardio: pytapo é pesado e síncrono

            try:
                self._tapo = Tapo(
                    self.host, "admin", self._password, self._password, retryStok=False
                )
            except Exception as err:  # pytapo só levanta Exception genérica
                if _is_auth(err):
                    raise TapoAuthError(str(err)) from err
                raise
        return self._tapo

    def _multi(self, queries: list[tuple[str, dict]]) -> dict[str, Any]:
        try:
            return self._multi_once(queries)
        except TapoAuthError:
            time.sleep(3)
            return self._multi_once(queries)

    def _multi_once(self, queries: list[tuple[str, dict]]) -> dict[str, Any]:
        with self._lock:
            return self._multi_locked(queries)

    def _multi_locked(self, queries: list[tuple[str, dict]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for i in range(0, len(queries), BATCH):
            chunk = queries[i : i + BATCH]
            try:
                resp = self._client().performRequest(
                    {
                        "method": "multipleRequest",
                        "params": {"requests": [{"method": m, "params": p} for m, p in chunk]},
                    }
                )
            except Exception as err:
                # Erro com código da câmera (ex.: -40214, a C200 v3 ocupada) mantém a sessão;
                # só auth/rede pedem login novo — relogar à toa empurra pro lockout de 30 min.
                if _is_auth(err) or "Response:" not in str(err):
                    self._tapo = None
                if _is_auth(err):
                    raise TapoAuthError(str(err)) from err
                raise
            for r in resp["result"]["responses"]:
                if r.get("error_code") == 0:
                    out[r["method"]] = r.get("result", {})
        return out

    def device_info(self) -> dict:
        """basic_info da câmera (modelo, firmware, MAC, alias) — valida login."""
        return self._multi([LOCAL_QUERIES[0]])["getDeviceInfo"]["device_info"]["basic_info"]

    def call(self, method: str, params: dict) -> dict:
        """Executa um set*/do* e devolve a resposta (levanta se error_code != 0)."""
        with self._lock:
            resp = self._client().performRequest(
                {"method": "multipleRequest", "params": {"requests": [{"method": method, "params": params}]}}
            )["result"]["responses"][0]
        if resp.get("error_code") != 0:
            raise TapoCommandError(method, resp.get("error_code"))
        return resp.get("result", {})

    def legacy(self, body: dict) -> dict:
        """Formato antigo {"method": "do"/"set", ...} — a sirene da C200 só aceita assim."""
        with self._lock:
            return self._client().performRequest(body)

    def fetch_live(self) -> dict[str, Any]:
        now = int(time.time())
        return {**self._multi([LIVE_QUERY, (
            "searchDetectionList",
            {"playback": {"search_detection_list": {
                "start_index": 0, "end_index": 50, "channel": 0,
                "start_time": now - 120, "end_time": now + 60,
            }}},
        )]), "_fetched_at": now}

    def fetch(self) -> dict[str, Any]:
        now = int(time.time())
        data = self._multi(LOCAL_QUERIES)
        if (uid := data.get("getUserID", {}).get("user_id")) is not None:
            self._user_id = uid
        history: list[tuple[str, dict]] = [
            (
                "searchDetectionList",
                {"playback": {"search_detection_list": {
                    "start_index": 0, "end_index": 999, "channel": 0,
                    "start_time": now - 86400, "end_time": now,
                }}},
            )
        ]
        local_day = _camera_day(data)
        if local_day and self._user_id is not None:
            history.append(
                (
                    "searchVideoOfDay",
                    {"playback": {"search_video_utility": {
                        "channel": 0, "date": local_day, "start_index": 0,
                        "end_index": 999, "id": self._user_id,
                    }}},
                )
            )
        data.update(self._multi(history))
        data["_fetched_at"] = now
        return data


def _is_auth(err: Exception) -> bool:
    msg = str(err)
    return "Invalid authentication" in msg or "Suspension" in msg


def _camera_day(data: dict) -> str | None:
    local = data.get("getClockStatus", {}).get("system", {}).get("clock_status", {}).get("local_time")
    return local[:10].replace("-", "") if local else None


# ---------------------------------------------------------------- nuvem

APP_TYPE = "TP-Link_Tapo_Android"
APP_VER = "3.22.304"
ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"  # bs0/b.g() (prod)
SECRET_KEY = "6ed7d97f3e73467f8a5bab90b577ba4c"  # bs0/b.h() (prod)
CLOUD_BASE = "https://n-wap.i.tplinkcloud.com"  # bs0/b.i() (prod)


class TapoCloudError(Exception):
    def __init__(self, code: int, msg: str) -> None:
        super().__init__(f"{code}: {msg}")
        self.code = code


class TapoMFARequired(Exception):
    def __init__(self, process_id: str) -> None:
        super().__init__("MFA required")
        self.process_id = process_id


def _ssl_context() -> ssl.SSLContext:
    # Mesma raiz que o app embarca em mergedCA.pem; a TP-Link não usa CA pública.
    ctx = ssl.create_default_context(cafile=str(Path(__file__).with_name("tplink_cloud_ca.pem")))
    return ctx


def sign(body: bytes, path: str, nonce: str) -> dict[str, str]:
    """Headers do interceptor m7/r: HMAC-SHA1(SK, md5b64\\n9999999999\\nnonce\\npath)."""
    md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
    payload = f"{md5}\n9999999999\n{nonce}\n{path}".encode()
    sig = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha1).hexdigest()
    return {
        "Content-MD5": md5,
        "X-Authorization": f"Timestamp=9999999999, Nonce={nonce}, AccessKey={ACCESS_KEY}, Signature={sig}",
    }


class TapoCloud:
    def __init__(self, session: aiohttp.ClientSession, username: str, password: str,
                 terminal_uuid: str | None = None, token: str | None = None,
                 url: str | None = None) -> None:
        self._session = session
        self.username = username
        self._password = password
        self.terminal_uuid = terminal_uuid or uuid.uuid4().hex.upper()
        self.token = token
        self.url = url
        self._ssl = None

    async def _post(self, base: str, path: str, body: dict, token: bool = True) -> dict:
        if self._ssl is None:
            import asyncio

            self._ssl = await asyncio.get_running_loop().run_in_executor(None, _ssl_context)
        raw = json.dumps(body, separators=(",", ":")).encode()
        params = {
            "appName": APP_TYPE, "appVer": APP_VER, "netType": "wifi",
            "termID": self.terminal_uuid, "ospf": "Android 14", "brand": "TPLINK",
            "locale": "pt_BR", "termName": "Home Assistant",
        }
        if token and self.token:
            params["token"] = self.token
        headers = {"Content-Type": "application/json;charset=UTF-8", **sign(raw, path, str(uuid.uuid4()))}
        async with self._session.post(base + path, params=params, data=raw, headers=headers,
                                      ssl=self._ssl, timeout=aiohttp.ClientTimeout(total=30)) as r:
            res = await r.json(content_type=None)
        code = res.get("error_code", -1)
        if code != 0:
            raise TapoCloudError(code, res.get("msg", ""))
        return res.get("result") or {}

    async def login(self) -> None:
        st = await self._post(CLOUD_BASE, "/api/v2/account/getAccountStatusAndUrl",
                              {"appType": APP_TYPE, "cloudUserName": self.username}, token=False)
        self.url = st.get("appServerUrlV2") or st.get("appServerUrl")
        res = await self._post(self.url, "/api/v2/account/login", {
            "appType": APP_TYPE, "appVersion": APP_VER, "cloudUserName": self.username,
            "cloudPassword": self._password, "platform": "Android 14", "refreshTokenNeeded": True,
            "terminalUUID": self.terminal_uuid, "terminalName": "Home Assistant",
            "terminalMeta": "1", "supportBindAccount": False,
        }, token=False)
        if res.get("mfaProcessId") and not res.get("token"):
            raise TapoMFARequired(res["mfaProcessId"])
        self.token = res["token"]

    async def send_mfa_email(self) -> None:
        await self._post(self.url, "/api/v2/account/getEmailVC4TerminalMFA", {
            "appType": APP_TYPE, "cloudUserName": self.username,
            "cloudPassword": self._password, "terminalUUID": self.terminal_uuid, "locale": "pt_BR",
        }, token=False)

    async def check_mfa(self, process_id: str, code: str) -> None:
        res = await self._post(self.url, "/api/v2/account/checkMFACodeAndLogin", {
            "appType": APP_TYPE, "cloudUserName": self.username, "code": code,
            "mfaProcessId": process_id, "mfaType": 1, "terminalBindEnabled": True,
            "supportBindAccount": False,
        }, token=False)
        self.token = res["token"]

    async def _call(self, path: str, body: dict) -> dict:
        try:
            return await self._post(self.url, path, body)
        except TapoCloudError as err:
            if err.code not in (-20651, -20675):  # token expirado/inválido
                raise
            await self.login()
            return await self._post(self.url, path, body)

    async def devices(self) -> list[dict]:
        res = await self._call("/api/v2/common/getDeviceListByPage", {
            "deviceTypeList": ["SMART.IPCAMERA"], "index": 0, "limit": 50})
        return res.get("deviceList", [])

    async def notifications(self, hours: int = 24) -> list[dict]:
        """Central de notificações do app (NotificationCenterManager.V()).

        O servidor só responde em ordem ascendente a partir de indexTime (desc vem vazio).
        getDeviceMsgsByPage existe na API mas o app não usa e volta sempre vazio.
        """
        since = int(time.time() * 1000) - hours * 3600_000
        out: list[dict] = []
        index = 0
        for _ in range(20):  # 20 páginas × 50 = teto de 1000 notificações no período
            res = await self._call("/api/v2/common/getAppNotificationByPage", {
                "appType": APP_TYPE, "terminalUUID": self.terminal_uuid, "mobileType": "ANDROID",
                "deviceToken": "", "locale": "pt_BR", "direction": "asc", "index": index,
                "indexTime": since, "limit": 50, "contentVersion": 3,
            })
            out += res.get("notifications", [])
            if not res.get("hasNextPage"):
                break
            index = res.get("currentIndex", index) + 1
        return out
