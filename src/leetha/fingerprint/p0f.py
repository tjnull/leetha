"""Match captured TCP handshakes against the supported p0f v3 fields."""

from __future__ import annotations


def _quirks(fields: dict) -> set[str] | None:
    required = ("df", "ip_id", "tcp_seq", "tcp_ack", "tcp_urgptr",
                "tcp_flags_int", "window_scale")
    if any(key not in fields for key in required):
        return None
    flags = fields["tcp_flags_int"]
    df = bool(fields["df"])
    quirks = set()
    if df:
        quirks.add("df")
        if fields["ip_id"]:
            quirks.add("id+")
    elif not fields["ip_id"]:
        quirks.add("id-")
    if flags & 0xC0:
        quirks.add("ecn")
    if not fields["tcp_seq"]:
        quirks.add("seq-")
    if flags & 0x10:
        if not fields["tcp_ack"]:
            quirks.add("ack-")
    elif fields["tcp_ack"]:
        quirks.add("ack+")
    if fields["tcp_urgptr"] and not flags & 0x20:
        quirks.add("uptr+")
    if flags & 0x20:
        quirks.add("urgf+")
    if flags & 0x08:
        quirks.add("pushf+")
    timestamps = fields.get("tcp_timestamps")
    if isinstance(timestamps, (list, tuple)) and len(timestamps) == 2:
        if not timestamps[0]:
            quirks.add("ts1-")
        if timestamps[1] and fields.get("tcp_flags") == "S":
            quirks.add("ts2+")
    if fields["window_scale"] is not None and fields["window_scale"] > 14:
        quirks.add("exws")
    return quirks


def match_score(signature: str, fields: dict) -> int | None:
    """Return a confidence ranking, or None when observed fields disagree.

    This deliberately skips p0f features the capture parser cannot represent,
    instead of treating an unobserved quirk as a wildcard.
    """
    parts = signature.split(":")
    if len(parts) != 8:
        return None
    version, ittl, olen, mss_rule, window_rule, options, quirks_rule, pclass = parts
    if version not in ("*", "4") or fields.get("p0f_options") != options:
        return None
    observed_quirks = _quirks(fields)
    if observed_quirks is None or set(filter(None, quirks_rule.split(","))) != observed_quirks:
        return None
    if pclass == "0" and fields.get("tcp_payload_len") != 0:
        return None
    if pclass == "+" and not fields.get("tcp_payload_len"):
        return None
    if pclass not in ("0", "+", "*"):
        return None
    if olen != "*" and (not olen.isdecimal() or fields.get("ip_options_len") != int(olen)):
        return None
    ttl = fields.get("ttl")
    if ittl != "*":
        if not ittl.isdecimal() or ttl is None or not 0 <= int(ittl) - int(ttl) <= 20:
            return None
    mss = fields.get("mss")
    if mss_rule != "*" and (not mss_rule.isdecimal() or mss != int(mss_rule)):
        return None
    if "," not in window_rule:
        return None
    window_expr, scale_expr = window_rule.split(",", 1)
    scale = fields.get("window_scale")
    if scale_expr != "*" and (not scale_expr.isdecimal() or
                              (scale or 0) != int(scale_expr)):
        return None
    window = fields.get("window_size")
    if window_expr.isdecimal():
        valid_window = window == int(window_expr)
    elif window_expr.startswith("mss*") and window_expr[4:].isdecimal() and mss:
        valid_window = window == mss * int(window_expr[4:])
    elif window_expr.startswith("mtu*") and window_expr[4:].isdecimal() and mss:
        valid_window = window == (mss + 40) * int(window_expr[4:])
    elif window_expr.startswith("%") and window_expr[1:].isdecimal():
        divisor = int(window_expr[1:])
        valid_window = bool(divisor and window is not None and window % divisor == 0)
    else:
        valid_window = window_expr == "*"
    if not valid_window:
        return None
    score = 4  # ordered TCP options are the strongest signal
    score += int(ittl != "*") + int(mss_rule != "*") + int(olen != "*")
    score += int(window_expr != "*") * 2 + int(scale_expr != "*")
    score += int(bool(quirks_rule))
    return score if score >= 7 else None
