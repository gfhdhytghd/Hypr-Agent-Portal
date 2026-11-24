"""Versioned replies for native Hyprland Lua dispatches."""

REPLY_PREFIX = "hypr-agent-portal/1 "


def lua_quote(value: str) -> str:
    """Return one Lua string literal containing the original UTF-8 bytes."""
    escapes = {34: r'\"', 92: r"\\", 10: r"\n", 13: r"\r", 9: r"\t"}
    parts = ['"']
    for byte in value.encode("utf-8"):
        if byte in escapes:
            parts.append(escapes[byte])
        elif 32 <= byte <= 126:
            parts.append(chr(byte))
        else:
            parts.append(f"\\{byte:03d}")
    parts.append('"')
    return "".join(parts)


def lua_dispatch_expression(factory_call: str) -> str:
    # Non-interactive 'dispatch' drops Lua return values. 'repl' with an
    # explicit expression prints the returned string in one IPC round trip.
    return (
        "return (function() "
        f"local r = hl.dispatch({factory_call}); "
        "if r == nil then return '' end; if r == true then return 'ok' end; "
        "if type(r) ~= 'table' or (r.protocol_version ~= nil and r.protocol_version ~= 1) "
        "or type(r.ok) ~= 'boolean' "
        f"then return '{REPLY_PREFIX}invalid' end; "
        f"if r.ok then return '{REPLY_PREFIX}ok' end; "
        f"return '{REPLY_PREFIX}error ' .. (r.error or 'native dispatch failed') "
        "end)()"
    )


def parse_lua_reply(output: str, *, allow_empty: bool = True) -> tuple[bool, str]:
    reply = output.strip()
    if not reply and allow_empty:
        return True, ""
    if reply in ("ok", REPLY_PREFIX + "ok"):
        return True, "ok"
    marker = REPLY_PREFIX + "error "
    if reply.startswith(marker) and reply[len(marker):]:
        return False, reply[len(marker):]
    return False, f"invalid native dispatch reply: {reply or 'empty response'}"
