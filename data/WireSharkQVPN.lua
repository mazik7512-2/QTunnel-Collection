local log_file = io.open("Z:\\Files\\temp-files\\wireshark_debug.log", "a")  -- Windows

function debug_log(msg)
    if log_file then
        log_file:write(os.date("%Y-%m-%d %H:%M:%S") .. " - " .. msg .. "\n")
        log_file:flush()  -- Важно! Сразу записываем на диск
    end
end

local fake_tls_rec = Proto("FakeTLS", "Fake TLS 1.3/QVPN")

-- Params

fake_tls_rec.prefs.proto = Pref.string("Transport protocol", "tcp", "Transport protocol for filter")
fake_tls_rec.prefs.port = Pref.uint("Port", 5151, "What port (src and dst both) will be filtered")

local fake_tls_record_type_names = { [0x17] = "Application Data" }
local fake_tls_record_ver_names = { [0x0300] = "SSL v3.0", [0x0301] = "TLS v1.0", [0x0302] = "TLS v1.1", [0x0303] = "TLS v1.2", [0x0304] = "TLS v1.3" }

local fake_tls_rec_type = ProtoField.uint8("FakeTLSRec.Type", "Fake tls record type", base.DEC, fake_tls_record_type_names)
local fake_tls_rec_ver = ProtoField.uint16("FakeTLSRec.Ver", "Fake tls record version", base.HEX, fake_tls_record_ver_names)
local fake_tls_rec_length = ProtoField.uint16("FakeTLSRec.Length", "Fake tls record length", base.DEC)
local FAKE_TLS_SIZE = 5

fake_tls_rec.fields = { fake_tls_rec_type, fake_tls_rec_ver, fake_tls_rec_length }

local packet_builder = Proto("PB_QVPN", "QVPN Packet Builder")
local PB_SIZE = 5

local pb_id = ProtoField.uint8("PacketBuilder.ID", "Packet Builder ID", base.DEC)
local pb_offset = ProtoField.uint16("PacketBuilder.Offset", "Packet Builder offset", base.DEC)
local pb_orig_size = ProtoField.uint16("PacketBuilder.OrigSize", "Packet Builder original size", base.DEC)

packet_builder.fields = { pb_id, pb_offset, pb_orig_size }

local qtunnel_proto = Proto("QVPN", "QVPN proto v0.5")
local QT_SIZE = 14

local qt_net_proto_names = { [4] = "IPv4", [6] = "IPv6" }
local qt_transport_proto_names = { [6] = "TCP", [17] = "UDP" }

local qt_net_proto = ProtoField.uint8("QTunnel.NetProto", "Net protocol", base.DEC, qt_net_proto_names)
local qt_transport_proto = ProtoField.uint8("QTunnel.TransportProto", "Transport protocol", base.DEC, qt_transport_proto_names)
local qt_src = ProtoField.ipv4("QTunnel.src", "Src ip")
local qt_src_port = ProtoField.uint16("QTunnel.src_port", "Src port", base.DEC)
local qt_dst = ProtoField.ipv4("QTunnel.dst", "Dest ip")
local qt_dst_port = ProtoField.uint16("QTunnel.dst_port", "Dst port", base.DEC)

local qt_proto_data = ProtoField.bytes("QTunnel.ProtoData", "QVPN Proto data")

qtunnel_proto.fields = { qt_net_proto, qt_transport_proto, qt_src, qt_src_port, qt_dst, qt_dst_port, qt_proto_data }


local tcp_proto_data = Proto("QVPNProtoTCPData", "TCP Proto data (QVPN)")

local tcp_pd_length = ProtoField.uint16("ProtoData.TCP.Length", "TCP Proto data Length", base.DEC)

local tcp_pd_seq = ProtoField.uint32("ProtoData.TCP.SEQ", "TCP SEQ (QVPN Proto data)", base.DEC)
local tcp_pd_ack = ProtoField.uint32("ProtoData.TCP.ACK", "TCP ACK (QVPN Proto data)", base.DEC)
local tcp_pd_flags = ProtoField.uint16("ProtoData.TCP.Flags", "TCP Flags (QVPN Proto data)", base.BIN)
local tcp_pd_offset = ProtoField.uint8("ProtoData.TCP.Offset", "TCP Offset (QVPN Proto data)", base.DEC)
local tcp_pd_window = ProtoField.uint16("ProtoData.TCP.Window", "TCP Window (QVPN Proto data)", base.DEC)
local tcp_pd_urgent = ProtoField.uint16("ProtoData.TCP.Urgent", "TCP Urgent pointer (QVPN Proto data)", base.DEC)

local tcp_pd_options = ProtoField.bytes("ProtoData.TCP.Options", "TCP Options (QVPN Proto data)")

tcp_proto_data.fields = { tcp_pd_length, tcp_pd_seq, tcp_pd_ack, tcp_pd_flags, tcp_pd_offset, tcp_pd_window, tcp_pd_urgent }


local tcp_proto_data_flags = Proto("TCPFlags", "TCP Flags")

-- Добавляем поля для отдельных флагов (используя маски)
local tcp_flag_fin = ProtoField.bool("ProtoData.TCP.Flags.FIN", "FIN", 1, nil, 0x01)
local tcp_flag_syn = ProtoField.bool("ProtoData.TCP.Flags.SYN", "SYN", 1, nil, 0x02)
local tcp_flag_rst = ProtoField.bool("ProtoData.TCP.Flags.RST", "RST", 1, nil, 0x04)
local tcp_flag_psh = ProtoField.bool("ProtoData.TCP.Flags.PSH", "PSH", 1, nil, 0x08)
local tcp_flag_ack = ProtoField.bool("ProtoData.TCP.Flags.ACK", "ACK", 1, nil, 0x10)
local tcp_flag_urg = ProtoField.bool("ProtoData.TCP.Flags.URG", "URG", 1, nil, 0x20)
local tcp_flag_ece = ProtoField.bool("ProtoData.TCP.Flags.ECE", "ECE", 1, nil, 0x40)
local tcp_flag_cwr = ProtoField.bool("ProtoData.TCP.Flags.CWR", "CWR", 1, nil, 0x80)
local tcp_flag_ns = ProtoField.bool("ProtoData.TCP.Flags.NS", "NS", 1, nil, 0x100)

local tcp_flags_arr = { tcp_flag_fin, tcp_flag_syn, tcp_flag_rst, tcp_flag_psh, tcp_flag_ack, tcp_flag_urg, tcp_flag_ece, tcp_flag_cwr, tcp_flag_ns }

tcp_proto_data_flags.fields = { tcp_flag_fin, tcp_flag_syn, tcp_flag_rst, tcp_flag_psh, tcp_flag_ack, tcp_flag_urg, tcp_flag_ece, tcp_flag_cwr, tcp_flag_ns }


-- Settings
local fake_tls_settings = { proto = "tcp", port = 5151 }




function packet_builder.dissector(buffer, pinfo, tree)
	
	local subtree = tree:add(packet_builder, buffer(), "QVPN Packet builder")
	
	-- Извлекаем PacketBuilder поля
    local pb_id_ = buffer(0, 1):le_uint()
    local pb_offset_ = buffer(1, 2):le_uint()
	local pb_orig_size_ = buffer(3, 2):le_uint()
	
    subtree:add(pb_id, buffer(0, 1))
    subtree:add(pb_offset, buffer(1, 2))
	subtree:add(pb_orig_size, buffer(3, 2))
	
end

function tcp_proto_data_flags.dissector(buffer, pinfo, tree)

	local real_flags = buffer(0, 2)
	local u_flags = buffer(0, 2):uint()
	local flags_int = real_flags:le_uint()
	
	local fin = u_flags & 0x01
	local syn = u_flags & 0x02
	local rst = u_flags & 0x04
	local psh = u_flags & 0x08
	local ack = u_flags & 0x10
	local urg = u_flags & 0x20
	local ece = u_flags & 0x40
	local cwr = u_flags & 0x80
	local ns = u_flags & 0x100
	
	local flags = { fin, syn, rst, psh, ack, urg, ece, cwr, ns }
	local flags_names = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS" }
	local flags_str = "TCP Proto data Flags [ "
	
	for i = 1, 9 do
	
		if flags[i] ~= 0 then
			flags_str = flags_str .. flags_names[i] .. " "
		end
		
	end
	flags_str = flags_str .. "]"
	
	local subtree = tree:add(tcp_proto_data_flags, buffer(0, 2), flags_str)
	
	
	subtree:add(tcp_flag_fin, real_flags)
	subtree:add(tcp_flag_syn, real_flags)
	subtree:add(tcp_flag_rst, real_flags)
	subtree:add(tcp_flag_psh, real_flags)
	subtree:add(tcp_flag_ack, real_flags)
	subtree:add(tcp_flag_urg, real_flags)
	subtree:add(tcp_flag_ece, real_flags)
	subtree:add(tcp_flag_cwr, real_flags)
	subtree:add(tcp_flag_ns, real_flags)
	

end

function tcp_proto_data.dissector(buffer, pinfo, tree)
	
	local subtree = tree:add(tcp_proto_data, buffer(), "TCP Proto Data (QVPN)")
	
	local pd_length = buffer(0, 2):le_uint()
	
	local pd_seq = buffer(2, 4):le_uint()
	local pd_ack = buffer(6, 4):le_uint()
	local pd_flags = buffer(10, 2):le_uint()
	local pd_offset = buffer(12, 1):le_uint()
	local pd_window = buffer(13, 2):le_uint()
	local pd_urgent = buffer(15, 2):le_uint()
	
	local pd_options = buffer(17):tvb()
	
	subtree:add(tcp_pd_length, buffer(0, 2))
	
	subtree:add(tcp_pd_seq, buffer(2, 4))
    subtree:add(tcp_pd_ack, buffer(6, 4))
	
	--subtree:add(tcp_pd_flags, buffer(10, 2))
	local flags = buffer(10, 2):tvb()
	tcp_proto_data_flags.dissector(flags, pinfo, subtree)
	
	subtree:add(tcp_pd_offset, buffer(12, 1))
    subtree:add(tcp_pd_window, buffer(13, 2))
	subtree:add(tcp_pd_urgent, buffer(15, 2))
	
	subtree:add(tcp_pd_options, buffer(17):tvb())
	
	return pd_length
end

function qtunnel_proto.dissector(buffer, pinfo, tree)
	
    -- Добавляем новый узел в дерево разбора
    local subtree = tree:add(qtunnel_proto, buffer(), "QVPN/QTunnel")
	
	
    local net_proto = buffer(0, 1):le_uint()
	local transport_proto = buffer(1, 1):le_uint()
	local src = buffer(2, 4):le_uint()
	local src_port = buffer(6, 2):le_uint()
	local dst = buffer(8, 4):le_uint()
	local dst_port = buffer(12, 2):le_uint()
	
	subtree:add(qt_net_proto, buffer(0, 1))
    subtree:add(qt_transport_proto, buffer(1, 1))
	subtree:add(qt_src, buffer(2, 4))
	subtree:add(qt_src_port, buffer(6, 2))
    subtree:add(qt_dst, buffer(8, 4))
	subtree:add(qt_dst_port, buffer(12, 2))
	
	local proto_data = buffer(14):tvb()
	
	if transport_proto == 6 then
		tcp_proto_data.dissector(proto_data, pinfo, tree)
	end

end


function fake_tls_rec.dissector(buffer, pinfo, tree)

	if buffer:len() < 25 then
		return 0
	end

	local content_type = buffer(0, 1):le_uint()
	local version = buffer(1, 2):le_uint()
	local record_length = buffer(3, 2):le_uint()
	
	if content_type ~= 0x17 then
		print("Invalid content_type. Calling default TLS dissector...")
		local tls_dissector = Dissector.get("tls")
		if tls_dissector then
			tls_dissector:call(buffer, pinfo, tree)
		end
		return
	end

    pinfo.cols.protocol = "FakeTLS + QVPN/QTunnel"

    local subtree = tree:add(fake_tls_rec, buffer(), "Fake TLS Record")
	
	subtree:add(fake_tls_rec_type, buffer(0, 1))
	subtree:add(fake_tls_rec_ver, buffer(1, 2))
	subtree:add(fake_tls_rec_length, buffer(3, 2))
	
	local pb_payload = buffer(FAKE_TLS_SIZE):tvb()
	packet_builder.dissector(pb_payload, pinfo, subtree)
	
	local qt_payload = buffer(FAKE_TLS_SIZE + PB_SIZE):tvb()
	qtunnel_proto.dissector(qt_payload, pinfo, subtree)
	
end


function fake_tls_rec.prefs_changed()
    if fake_tls_settings.port ~= fake_tls_rec.prefs.port then
        -- Удаляем старую регистрацию
        if fake_tls_settings.port ~= 0 then
            DissectorTable.get(fake_tls_settings.proto .. ".port"):remove(fake_tls_settings.port, fake_tls_rec)
        end
        
        -- Обновляем значение
        fake_tls_settings.port = fake_tls_rec.prefs.port
        
        -- Регистрируем на новом порту
        if fake_tls_settings.port ~= 0 then
            DissectorTable.get(fake_tls_settings.proto .. ".port"):add(fake_tls_settings.port, fake_tls_rec)
        end
    end
end


DissectorTable.get(fake_tls_settings.proto .. ".port"):add(fake_tls_settings.port, fake_tls_rec)


local fake_tls_payload_table = DissectorTable.new("FakeTLS.QVPN.Payload", "FakeTLS/QVPN Payload", ftypes.NONE)
local qvpn_payload_table = DissectorTable.new("QVPN.Payload", "QVPN Payload", ftypes.NONE)


-- Регистрируем QVPN в таблице
local dtq = DissectorTable.get("QVPN.Payload")
if dt then
    dtq:add_for_decode_as(qtunnel_proto)
end

local dtfq = DissectorTable.get("FakeTLS.QVPN.Payload")
if dtfq then
	dtfq:add_for_decode_as(fake_tls_rec)
end

-- Функция-проверка. Возвращает true, если пакет наш, иначе false.
local function heuristic_checker(tvb, pinfo, tree)
    -- 1. Проверяем длину (минимум 25 байт для QVPN)
    if tvb:len() < 25 then
        return false
    end

    -- 2. Проверяем сигнатуру протокола.
    local content_type = tvb(0, 1):uint()
    local version = tvb(1, 2):le_uint()

    if content_type == 0x17 and version == 0x0303 then
        -- 3. Если сигнатура совпала, вызываем основной диссектор для разбора
        fake_tls_rec.dissector(tvb, pinfo, tree)
        return true -- Сообщаем Wireshark, что пакет наш
    end

    -- Если сигнатура не совпала, возвращаем false
    return false
end

--fake_tls_rec:register_heuristic("tcp", heuristic_checker)