-- Copyright (c) 2018 Viveris Technologies <adrien.destugues@opensource.viveris.fr>
-- Copyright (c) 2014 Peter Zotov <whitequark@whitequark.org>
-- Copyright (c) 2011, Robert G. Jakabosky <bobby@sharedrealm.com> All rights reserved.

-- cache globals to local for speed.
local format=string.format
local tostring=tostring
local tonumber=tonumber
local sqrt=math.sqrt
local pairs=pairs

-- wireshark API globals
local Pref = Pref
local Proto = Proto
local ProtoField = ProtoField
local DissectorTable = DissectorTable
local ByteArray = ByteArray
local PI_MALFORMED = PI_MALFORMED
local PI_ERROR = PI_ERROR

-- zmq protocol example
-- declare our protocol
local zmtp_proto = Proto("zmtp", "ZMTP", "ZeroMQ Message Transport Protocol")

-- setup preferences
zmtp_proto.prefs["tcp_port_start"] =
        Pref.string("TCP port range start", "5555", "First TCP port to decode as this protocol")
zmtp_proto.prefs["tcp_port_end"] =
        Pref.string("TCP port range end", "5555", "Last TCP port to decode as this protocol")
zmtp_proto.prefs["protocol"] =
        Pref.string("Encapsulated protocol", "", "Subdissector to invoke")

-- current preferences settings.
local current_settings = {
        tcp_port_start = -1,
        tcp_port_end = -1,
        protocol = "",
}

-- setup protocol fields.

vs_stype = {
    [0] = "pair",
    [1] = "publish",
    [2] = "subscribe",
    [3] = "request",
    [4] = "reply",
    [5] = "dealer",
    [6] = "router",
    [7] = "pull",
    [8] = "push"
}

zmtp_proto.fields = {}
local fds = zmtp_proto.fields
fds.greeting = ProtoField.new("Signature", "zmtp.greeting", ftypes.BYTES)
fds.version = ProtoField.new("ZMTP Version", "zmtp.greeting.version", ftypes.UINT16, nil, base.HEX)
fds.version_major = ProtoField.new("ZMTP Major Version", "zmtp.greeting.version.major", ftypes.UINT8, nil, base.DEC)

fds.version_minor = ProtoField.new("ZMTP Minor Version", "zmtp.greeting.version.minor", ftypes.UINT8, nil, base.DEC)
fds.mechanism = ProtoField.new("ZMTP Security Mechanism", "zmtp.greeting.mechanism", ftypes.STRINGZ)
fds.as_server = ProtoField.new("Is a ZMTP Server", "zmtp.greeting.as_server", ftypes.BOOLEAN)

fds.stype = ProtoField.new("Socket type", "zntp.stype", ftypes.UINT8, vs_stype, base.HEX)

fds.frame = ProtoField.new("Frame", "zmtp.frame", ftypes.BYTES)
fds.flags = ProtoField.new("Flags", "zmtp.frame.flags", ftypes.UINT8, nil, base.HEX, "0xFF")
fds.flags_more = ProtoField.new("Has More", "zmtp.frame.flags.more", ftypes.UINT8, {[1]="Yes",[0]="No"}, base.DEC, "0x01")
fds.flags_long = ProtoField.new("64-bit Length", "zmtp.frame.flags.64bit", ftypes.UINT8, {[1]="Yes",[0]="No"}, base.DEC, "0x02")
fds.flags_cmd = ProtoField.new("Is Command", "zmtp.frame.flags.command", ftypes.UINT8, {[1]="Yes",[0]="No"}, base.DEC, "0x04")
fds.length = ProtoField.new("Payload Length", "zmtp.frame.length", ftypes.UINT64, nil, base.DEC)
fds.protocol = ProtoField.new("Protocol", "zmtp.frame.protocol", ftypes.STRING, nil, base.NONE, 0, "Set protocol in Preferences → ZMTP")
fds.command_name = ProtoField.new("Command Name", "zmtp.command.name", ftypes.STRING)
fds.cmd_unknown_data = ProtoField.new("Unknown Command", "zmtp.command.unknown", ftypes.BYTES)
fds.cmd_ready = ProtoField.new("READY Command", "zmtp.command.ready", ftypes.BYTES)
fds.cmd_ready_curvezmq_nonce = ProtoField.new("CurveZMQ Server Nonce", "zmtp.command.ready.curvezmq.nonce", ftypes.BYTES)
fds.cmd_ready_curvezmq_box = ProtoField.new("CurveZMQ Box (metadata)", "zmtp.command.ready.curvezmq.box", ftypes.BYTES)
fds.cmd_initiate = ProtoField.new("INITIATE Command", "zmtp.command.initiate", ftypes.BYTES)
fds.cmd_initiate_curvezmq_cookie = ProtoField.new("CurveZMQ Server Cookie", "zmtp.command.initiate.curvezmq.cookie", ftypes.BYTES)
fds.cmd_initiate_curvezmq_nonce = ProtoField.new("CurveZMQ Client Nonce", "zmtp.command.initiate.curvezmq.nonce", ftypes.BYTES)
fds.cmd_initiate_curvezmq_box = ProtoField.new("CurveZMQ Box (client permanent public key, vouch, metadata)", "zmtp.command.initiate.curvezmq.box", ftypes.BYTES)
fds.cmd_metadata_key = ProtoField.new("Metadata Key", "zmtp.command.metadata.key", ftypes.STRING)
fds.cmd_metadata_value = ProtoField.new("Metadata Value", "zmtp.command.metadata.value", ftypes.STRING)
fds.cmd_hello = ProtoField.new("HELLO Command", "zmtp.command.hello", ftypes.BYTES)
fds.cmd_hello_username = ProtoField.new("Username", "zmtp.command.hello.username", ftypes.STRING)
fds.cmd_hello_password = ProtoField.new("Password", "zmtp.command.hello.password", ftypes.STRING)
fds.cmd_hello_curvezmq_version = ProtoField.new("CurveZMQ Version", "zmtp.command.hello.curvezmq.version", ftypes.UINT16, nil, base.HEX)
fds.cmd_hello_curvezmq_version_major = ProtoField.new("CurveZMQ Major", "zmtp.command.hello.curvezmq.version.major", ftypes.UINT8, nil, base.DEC)
fds.cmd_hello_curvezmq_version_minor = ProtoField.new("CurveZMQ Minor", "zmtp.command.hello.curvezmq.version.minor", ftypes.UINT8, nil, base.DEC)
fds.cmd_hello_curvezmq_padding = ProtoField.new("CurveZMQ Padding", "zmtp.command.hello.curvezmq.padding", ftypes.BYTES)
fds.cmd_hello_curvezmq_pubkey = ProtoField.new("CurveZMQ Transient Public Key", "zmtp.command.hello.curvezmq.pubkey", ftypes.BYTES)
fds.cmd_hello_curvezmq_nonce = ProtoField.new("CurveZMQ Nonce", "zmtp.command.hello.curvezmq.nonce", ftypes.BYTES)
fds.cmd_hello_curvezmq_signature = ProtoField.new("CurveZMQ Signature", "zmtp.command.hello.curvezmq.Signature", ftypes.BYTES)
fds.cmd_welcome = ProtoField.new("WELCOME Command", "zmtp.command.welcome", ftypes.BYTES)
fds.cmd_welcome_curvezmq_nonce = ProtoField.new("CurveZMQ Server Nonce", "zmtp.command.welcome.curvezmq.nonce", ftypes.BYTES)
fds.cmd_welcome_curvezmq_box = ProtoField.new("CurveZMQ Box (server public transient key, server cookie)", "zmtp.command.welcome.curvezmq.box", ftypes.BYTES)
fds.message = ProtoField.new("Encrypted MESSAGE", "zmtp.message", ftypes.BYTES)
fds.message_curvezmq_nonce = ProtoField.new("CurveZMQ Message Nonce", "zmtp.message.curvezmq.nonce", ftypes.BYTES)
fds.message_curvezmq_box = ProtoField.new("CurveZMQ Message Box (flags, payload)", "zmtp.message.curvezmq.box", ftypes.BYTES)
fds.cmd_error = ProtoField.new("ERROR Command", "zmtp.command.error", ftypes.BYTES)
fds.cmd_error_reason = ProtoField.new("ERROR Reason", "zmtp.command.error.reason", ftypes.STRING)
fds.cmd_ping = ProtoField.new("PING Command", "zmtp.command.ping", ftypes.BYTES)
fds.cmd_ping_ttl = ProtoField.new("Time To Live (deciseconds)", "zmtp.command.ping.ttl", ftypes.UINT16)
fds.cmd_ping_context = ProtoField.new("Context", "zmtp.command.ping.context", ftypes.STRING)
fds.cmd_pong = ProtoField.new("PONG Command", "zmtp.command.pong", ftypes.BYTES)
fds.cmd_pong_context = ProtoField.new("Context", "zmtp.command.pong.context", ftypes.STRING)

local tcp_stream_id = Field.new("tcp.stream")
local subdissectors = DissectorTable.new("zmtp.protocol", "ZMTP", ftypes.STRING)

-- un-register zmq to handle tcp port range
local function unregister_tcp_port_range(start_port, end_port)
        if not start_port or start_port <= 0 or not end_port or end_port <= 0 then
                return
        end
        local tcp_port_table = DissectorTable.get("tcp.port")
        for port = start_port,end_port do
                tcp_port_table:remove(port,zmtp_proto)
        end
end

-- register zmq to handle tcp port range
local function register_tcp_port_range(start_port, end_port)
        if not start_port or start_port <= 0 or not end_port or end_port <= 0 then
                return
        end
        local tcp_port_table = DissectorTable.get("tcp.port")
        for port = start_port,end_port do
                tcp_port_table:add(port,zmtp_proto)
        end
end

-- handle preferences changes.
function zmtp_proto.init(arg1, arg2)
        local old_start, old_end
        local new_start, new_end
        -- check if preferences have changed.
        for pref_name,old_v in pairs(current_settings) do
                local new_v = zmtp_proto.prefs[pref_name]
                if new_v ~= old_v then
                        if pref_name == "tcp_port_start" then
                                old_start = old_v
                                new_start = new_v
                        elseif pref_name == "tcp_port_end" then
                                old_end = old_v
                                new_end = new_v
                        end
                        -- save new value.
                        current_settings[pref_name] = new_v
                end
        end
        -- un-register old port range
        if old_start and old_end then
                unregister_tcp_port_range(tonumber(old_start), tonumber(old_end))
        end
        -- register new port range.
        if new_start and new_end then
                register_tcp_port_range(tonumber(new_start), tonumber(new_end))
        end
end

local stream_mechanisms = {}

local function zmq_dissect_frame(buffer, pinfo, frame_tree, tap, toplevel_tree)
        local flags_rang = buffer(0, 1)
        local flags = flags_rang:uint()

        if flags == 0xff then
                -- greeting
                frame_tree:add(fds.greeting, buffer(0, 10))
                frame_tree:set_text(format("Greeting"))

                local version_tree = frame_tree:add(fds.version, buffer(10, 2))
                local version_major_rang = buffer(10, 1)
                version_major = version_major_rang:uint()
                if version_major >= 2 then
                    version_tree:add(fds.version_major, version_major_rang)
                    local version_minor_rang = buffer(11, 1)
                    version_tree:add(fds.version_minor, version_minor_rang)
                    local mechanism_rang = buffer(12, 20)
                    frame_tree:add(fds.mechanism, mechanism_rang)
                    local as_server_rang = buffer(32, 1)
                    frame_tree:add(fds.as_server, as_server_rang)

                    tap.mechanism = mechanism_rang:stringz()
                    stream_mechanisms[tcp_stream_id().value] = tap.mechanism

                    if tap.mechanism == "NULL" then
                        return format("Greeting (ZMTP %d.%d, %s Mechanism)",
                                      version_major_rang:uint(),
                                      version_minor_rang:uint(),
                                      mechanism_rang:string())
                    else
                        local role
                        if as_server_rang:uint() == 1 then role = "Server" else role = "Client" end
                        return format("Greeting (ZMTP %d.%d, %s Mechanism, %s)",
                                      version_major_rang:uint(),
                                      version_minor_rang:uint(),
                                      mechanism_rang:string(), role)
                    end
                else
                    version_tree:add(fds.version_major, version_major_rang)
                    local type_rang = buffer(11, 1)
                    frame_tree:add(fds.stype, type_rang)
                    return format("Greeting (ZMTP %d), %s",
                                      version_major_rang:uint(),
                                      vs_stype[type_rang:uint()])
                end
        end

        local flags_tree = frame_tree:add(fds.flags, buffer(0, 1))
        flags_tree:add(fds.flags_more, buffer(0, 1))
        flags_tree:add(fds.flags_long, buffer(0, 1))
        flags_tree:add(fds.flags_cmd, buffer(0, 1))

        local flag_more = (bit.band(flags, 0x01) ~= 0)
        local flag_long = (bit.band(flags, 0x02) ~= 0)
        local flag_cmd  = (bit.band(flags, 0x04) ~= 0)

        local len_rang
        local body_offset
        local body_len
        if flag_long then -- LONG
                len_rang = buffer(1, 8)
                -- not before wireshark 1.11; http://wiki.wireshark.org/LuaAPI/Int64
                -- body_len = len_rang:uint64():tonumber()
                body_len = tonumber(tostring(len_rang:uint64()))
                body_offset = 9
        else
                len_rang = buffer(1, 1)
                body_len = len_rang:uint()
                body_offset = 2
        end
        frame_tree:add(fds.length, len_rang)

        local flags_desc = {}
        if flag_more then table.insert(flags_desc, "More") end
        if flag_cmd  then table.insert(flags_desc, "Command") end

        if #flags_desc > 0 then
                flags_tree:append_text(format(" (%s)", table.concat(flags_desc, ", ")))
        end

        tap.body_bytes = tap.body_bytes + body_len

        local has_more = ""
        if flag_more then
                has_more = " [Has More]"
        end

        local mechanism = stream_mechanisms[tcp_stream_id().value]
        local body_rang = buffer(body_offset, body_len)
        if flag_cmd then
                tap.commands = tap.commands + 1

                local cmd_name_len = body_rang:range(0, 1):uint()
                local cmd_name_rang = body_rang:range(1, cmd_name_len)
                local cmd_name = cmd_name_rang:string()
                frame_tree:add(fds.command_name, cmd_name_rang)

                local cmd_data_rang
                if body_rang:len() > 1 + cmd_name_len then
                        cmd_data_rang = body_rang:range(1 + cmd_name_len)
                end

                local function parse_metadata(cmd_tree)
                        local metadata = {}
                        local md_offset = 0
                        while md_offset < cmd_data_rang:len() do
                                local key_len = cmd_data_rang:range(md_offset, 1):uint()
                                local key_rang = cmd_data_rang:range(md_offset + 1, key_len)
                                cmd_tree:add(fds.cmd_metadata_key, key_rang)
                                md_offset = md_offset + 1 + key_len

                                local value_len = cmd_data_rang:range(md_offset, 4):uint()
                                if value_len > 0 then
                                        local value_rang = cmd_data_rang:range(md_offset + 4, value_len)
                                        cmd_tree:add(fds.cmd_metadata_value, value_rang)
                                        md_offset = md_offset + 4 + value_len

                                        table.insert(metadata, format("%s: %s",
                                                        key_rang:string(), value_rang:string()))
                                else
                                        md_offset = md_offset + 4

                                        table.insert(metadata, format("%s: (empty)",
                                                        key_rang:string()))
                                end
                        end

                        return table.concat(metadata, ", ")
                end

                if cmd_name == "READY" and mechanism ~= "CURVE" then
                        local ready_tree = frame_tree:add(fds.cmd_ready, cmd_data_rang)
                        frame_tree:set_text(format("Command READY%s: %s",
                                            has_more, parse_metadata(ready_tree)))
                elseif cmd_name == "READY" and mechanism == "CURVE" then
                        local ready_tree = frame_tree:add(fds.cmd_ready, cmd_data_rang)
                        ready_tree:add(fds.cmd_ready_curvezmq_nonce,
                                         cmd_data_rang:range(0, 8))
                        ready_tree:add(fds.cmd_ready_curvezmq_box,
                                         cmd_data_rang:range(8, cmd_data_rang:len() - 8))
                        frame_tree:set_text(format("Command READY"))
                elseif cmd_name == "HELLO" and mechanism == "PLAIN" then
                        local hello_tree = frame_tree:add(fds.cmd_hello, cmd_data_rang)

                        local username_len = cmd_data_rang:range(0, 1):uint()
                        local username_rang
                        if username_len > 0 then
                                username_rang = cmd_data_rang:range(1, username_len)
                        end

                        local password_len = cmd_data_rang:range(1 + username_len, 1):uint()
                        local password_rang
                        if password_len > 0 then
                                password_rang = cmd_data_rang:range(1 + username_len + 1, password_len)
                        end

                        local username
                        if username_rang then
                                username = username_rang:string()
                                hello_tree:add(fds.cmd_hello_username, username_rang)
                        else
                                username = "(empty)"
                        end

                        local password
                        if password_rang then
                                password = password_rang:string()
                                hello_tree:add(fds.cmd_hello_password, password_rang)
                        else
                                password = "(empty)"
                        end

                        frame_tree:set_text(format("Command HELLO%s: Username: %s, Password: %s",
                                            has_more, username, password))
                elseif cmd_name == "HELLO" and mechanism == "CURVE" then
                        local hello_tree = frame_tree:add(fds.cmd_hello, cmd_data_rang)

                        local ver_major = cmd_data_rang:range(0, 1)
                        local ver_minor = cmd_data_rang:range(1, 1)
                        local version_tree = hello_tree:add(fds.cmd_hello_curvezmq_version,
                                                            cmd_data_rang:range(0, 2))
                        version_tree:add(fds.cmd_hello_curvezmq_version_major, ver_major)
                        version_tree:add(fds.cmd_hello_curvezmq_version_minor, ver_minor)

                        if ver_major:uint() == 1 and ver_minor:uint() == 0 then
                                local padding_rang = cmd_data_rang:range(2, 72)
                                local padding_tree = hello_tree:add(fds.cmd_hello_curvezmq_padding, padding_rang)
                                if padding_rang:string() ~= string.rep("\0", 72) then
                                        padding_tree:add_expert_info(PI_PROTOCOL, PI_ERROR,
                                                                     "Non-zero padding")
                                end

                                hello_tree:add(fds.cmd_hello_curvezmq_pubkey,
                                               cmd_data_rang:range(74, 32))
                                hello_tree:add(fds.cmd_hello_curvezmq_nonce,
                                               cmd_data_rang:range(106, 8))
                                hello_tree:add(fds.cmd_hello_curvezmq_signature,
                                               cmd_data_rang:range(114, 80))
                        else
                                version_tree:add_expert_info(PI_UNDECODED, PI_ERROR,
                                                             "Unsupported CurveZMQ version")
                        end

                        frame_tree:set_text(format("Command HELLO%s: CurveZMQ %d.%d",
                                            has_more, ver_major:uint(), ver_minor:uint()))
                elseif cmd_name == "WELCOME" and mechanism == "CURVE" then
                        local welcome_tree = frame_tree:add(fds.cmd_welcome, cmd_data_rang)

                        welcome_tree:add(fds.cmd_welcome_curvezmq_nonce,
                                         cmd_data_rang:range(0, 16))
                        welcome_tree:add(fds.cmd_welcome_curvezmq_box,
                                         cmd_data_rang:range(16, 144))

                        frame_tree:set_text(format("Command WELCOME"))
                elseif cmd_name == "INITIATE" and mechanism == "PLAIN" then
                        local initiate_tree = frame_tree:add(fds.cmd_initiate, cmd_data_rang)
                        frame_tree:set_text(format("Command INITIATE%s: %s",
                                            has_more, parse_metadata(initiate_tree)))
                elseif cmd_name == "INITIATE" and mechanism == "CURVE" then
                        local initiate_tree = frame_tree:add(fds.cmd_initiate, cmd_data_rang)

                        initiate_tree:add(fds.cmd_initiate_curvezmq_cookie,
                                         cmd_data_rang:range(0, 96))
                        initiate_tree:add(fds.cmd_initiate_curvezmq_nonce,
                                         cmd_data_rang:range(96, 8))
                        initiate_tree:add(fds.cmd_initiate_curvezmq_box,
                                         cmd_data_rang:range(104, cmd_data_rang:len() - 104))

                        frame_tree:set_text(format("Command INITIATE"))
                elseif cmd_name == "ERROR" then
                        local error_tree = frame_tree:add(fds.cmd_error, cmd_data_rang)

                        local reason_len = cmd_data_rang:range(0, 1):uint()
                        local reason_rang = cmd_data_rang:range(1, reason_len)
                        error_tree:add(fds.cmd_error_reason, reason_rang)

                        frame_tree:set_text(format("Command ERROR%s: %s",
                                            has_more, reason_rang:string()))
                elseif cmd_name == "PING" then
                        local ping_tree = frame_tree:add(fds.cmd_ping, cmd_data_rang)
                        local ping_ttl = cmd_data_rang:range(0, 2)
                        local ttl_tree = ping_tree:add(fds.cmd_ping_ttl,
                                                       cmd_data_rang:range(0, 2))
                        if cmd_data_rang:len() - 2 > 0 then
                                local ping_context = cmd_data_rang:range(2, cmd_data_rang:len() - 2)
                                local ttl_tree = ping_tree:add(fds.cmd_ping_context,
                                                           ping_context)
                                frame_tree:set_text(format("Command PING%s: TTL: %d Context: %s",
                                                has_more, ping_ttl:uint(), ping_context))
                        else
                                frame_tree:set_text(format("Command PING%s: TTL: %d",
                                                has_more, ping_ttl:uint()))
                        end
                elseif cmd_name == "PONG" then
                        if cmd_data_rang then
                                local pong_tree = frame_tree:add(fds.cmd_pong, cmd_data_rang)
                                    local pong_context = cmd_data_rang:range(0, cmd_data_rang:len())
                                    local context_tree = pong_tree:add(fds.cmd_pong_context,
                                                               pong_context)
                                    frame_tree:set_text(format("Command PONG%s: Context: %s",
                                                    has_more, pong_context))
                        end
                else
                        if cmd_data_rang then
                                frame_tree:add(fds.cmd_unknown_data, cmd_data_rang)
                                frame_tree:set_text(format("Command %s%s: %s",
                                                    cmd_name, has_more, tostring(cmd_data_rang)))
                        else
                                frame_tree:set_text(format("Command %s%s",
                                                    cmd_name, has_more))
                        end
                end

                return format("Command (%s)", cmd_name)
        else
                tap.messages = tap.messages + 1

                if mechanism == "CURVE" and body_len >= 33 then
                        local cmd_name_len = body_rang:range(0, 1):uint()
                        if cmd_name_len == 7 then
                                local cmd_name_rang = body_rang:range(1, cmd_name_len)
                                local cmd_name = cmd_name_rang:string()
                                frame_tree:add(fds.command_name, cmd_name_rang)

                                local cmd_data_rang
                                if body_rang:len() > 1 + cmd_name_len then
                                        cmd_data_rang = body_rang:range(1 + cmd_name_len)
                                end
                                if cmd_name == "MESSAGE" then
                                        local message_tree = frame_tree:add(fds.message, cmd_data_rang)

                                        message_tree:add(fds.message_curvezmq_nonce,
                                                         cmd_data_rang:range(0, 8))
                                        message_tree:add(fds.message_curvezmq_box,
                                                         cmd_data_rang:range(8, cmd_data_rang:len() - 8))

                                        frame_tree:set_text(format("MESSAGE"))
                                end
                        end
                elseif body_len > 0 then
                        frame_tree:add(fds.protocol, current_settings.protocol):set_generated()

                        subdissectors:try(current_settings.protocol, body_rang:tvb(), pinfo, toplevel_tree)

                        frame_tree:set_text(format("Data%s, Length: %u",
                                            has_more, body_len, tostring(body_rang)))
                        if (subdissectors:get_dissector(current_settings.protocol)) then
                            return nil
                        else
                            return "Data"
                        end
                else
                        frame_tree:set_text(format("Empty%s", has_more))
                        return "Empty"
                end
        end
end

local DESEGMENT_ONE_MORE_SEGMENT = 0x0fffffff
local DESEGMENT_UNTIL_FIN        = 0x0ffffffe

-- packet dissector
function zmtp_proto.dissector(tvb, pinfo, tree)
        local offset = 0
        local rang
        local zmq_frames
        local tap  = {}
        local desc = {}

        tap.mechanism = ""
        tap.frames = 0
        tap.commands = 0
        tap.messages = 0
        tap.body_bytes = 0

        pinfo.cols.info:clear()
        subdissector_found = false

        local function ensure_length(len)
                if offset + len > tvb:len() then
                        pinfo.desegment_offset = offset
                        pinfo.desegment_len    = DESEGMENT_ONE_MORE_SEGMENT
                        return false
                else
                        return true
                end
        end

        -- print(format("zmtp_proto.dissector: offset:%d len:%d reported_len:%d", offset, tvb:len(), tvb:reported_len()), tvb(offset, 5))

        while offset < tvb:len() do
                if not ensure_length(1) then break end

                -- decode flags
                rang = tvb(offset, 1)
                local flags = rang:uint()
                if flags == 0xff then
                        -- greeting
                        if not ensure_length(12) then break end
                        local version_major_rang = tvb(offset + 10, 1)
                        local version_major = version_major_rang:uint()
                        if version_major >= 2 then
                            if not ensure_length(64) then break end
                            pdu_len = 64
                        else
                            pdu_len = 12
                        end
                elseif (bit.band(flags, 0x02) ~= 0) then
                        -- long frame
                        if not ensure_length(9) then break end
                        rang = tvb(offset + 1, 8)
                        -- not before wireshark 1.11; http://wiki.wireshark.org/LuaAPI/Int64
                        -- frame_len = rang:uint64():tonumber()
                        frame_len = tonumber(tostring(rang:uint64()))
                        pdu_len = frame_len + 9
                else
                        -- short frame
                        if not ensure_length(2) then break end
                        rang = tvb(offset + 1, 1)
                        frame_len = rang:uint()
                        pdu_len = frame_len + 2
                end

                -- provide hints to tcp
                if not pinfo.visited then
                        local remaining_bytes = tvb:len() - offset
                        if pdu_len > remaining_bytes then
                                pinfo.want_pdu_tracking = 2
                                pinfo.bytes_until_next_pdu = pdu_len - remaining_bytes
                        end
                end

                local truncated = false

                -- check if we need more bytes to dissect this frame.
                if offset + pdu_len > tvb:len() then
                        if tvb:len() == tvb:reported_len() then
                                pinfo.desegment_offset = offset
                                pinfo.desegment_len    = offset + pdu_len - tvb:len()
                                -- print(format("zmtp_proto.dissector: desegment offset:%d len:%d", pinfo.desegment_offset, pinfo.desegment_len))
                                break
                        else
                                -- already tried to dissect, but the desegmenter failed
                                pdu_len = tvb:len() - offset
                                truncated = true
                        end
                end

                if not zmq_frames then
                        zmq_frames = tree:add(zmtp_proto, tvb())
                end

                if (bit.band(flags, 0xf8) ~= 0) and flags ~= 0xff then
                        zmq_frames:add_expert_info(PI_REASSEMBLE, PI_ERROR, "Framing error")
                        return
                end

                -- dissect zmq frame
                rang = tvb(offset, pdu_len)
                local frame_tree = zmq_frames:add(fds.frame, rang)
                if truncated then
                        frame_tree:add_expert_info(PI_REASSEMBLE, PI_ERROR, "Message truncated")
                end
                local frame_desc = zmq_dissect_frame(rang:tvb(), pinfo, frame_tree, tap, tree)
                if frame_desc then
                    table.insert(desc, frame_desc)
                else
                    subdissector_found = true
                end
                tap.frames = tap.frames + 1

                -- step to next frame.
                local offset_before = offset
                offset = offset + pdu_len
                if offset < offset_before then break end
        end

        if zmq_frames then
                zmq_frames:set_text(format("ZeroMQ Message Transport Protocol, Frames: %u", tap.frames))
        end

        if tap.messages > 0 then
                table.insert(desc, format("Data Frames: %u", tap.messages))
        end

        -- Info column (only if subdissector did not fill it)
        if not subdissector_found then
            pinfo.cols.protocol = "ZMTP"
            pinfo.cols.info:prepend(table.concat(desc, "; "))
            --pinfo.tap_data = tap
        end

        return
end

-- register zmq to handle tcp ports 5550-5560
register_tcp_port_range(5550, 5560)

