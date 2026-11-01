"""Códigos de evento/gravação do firmware (enums do app Tapo 3.22.304)."""

# PlayBackEventType (libtapocameranetwork/business/model) — alarm_type do searchDetectionList
EVENT_TYPES = {
    1: "timing", 2: "motion", 3: "tamper", 4: "linecross", 5: "area_intrusion",
    6: "person", 7: "baby_cry", 8: "vehicle", 9: "pet", 10: "ring_alarm",
    11: "bark", 12: "meow", 13: "glass_break", 14: "smoke_alarm",
    15: "package_delivered", 16: "package_picked_up", 17: "doorbell_missed",
    18: "doorbell_answered", 19: "anti_theft", 23: "baby_leave", 24: "baby_caregiver",
    25: "baby_asleep", 26: "baby_awake", 27: "face_cover", 28: "safe_fence_out",
    30: "baby_motion", 31: "panoramic_video", 33: "animal", 34: "door_unlock",
    35: "gate_open", 36: "co_alarm",
}
# PlayBackVideoType — tipo do trecho no plano de gravação ("0000-2400:2")
RECORD_TYPES = {"1": "continuous", "2": "events", "3": "aov"}
