#include "qvpn_structures.hpp"
#include <sstream>
#include <iostream>
#include <qvpn_tools.hpp>
#include <ctime>


using Byte = QVPN::Core::DataStructures::Byte;
using UByte = QVPN::Core::DataStructures::UByte;
using UShort = QVPN::Core::DataStructures::UShort;
using UInt = QVPN::Core::DataStructures::UInt;
using ubyte_const_iter = QVPN::Core::DataStructures::ubyte_const_iter;
using HttpRequestType = QVPN::Core::DataStructures::HttpRequestType;

constexpr auto default_ip_quart_size = 5;
constexpr auto bytes_in_quartet = 4;
constexpr auto default_ip_bytes = default_ip_quart_size * bytes_in_quartet;

constexpr int default_tcp_quart_size = 5;
constexpr int default_tcp_size = default_tcp_quart_size * bytes_in_quartet;

constexpr int default_udp_size = 8;




QVPN::Core::DataStructures::Ipv4PacketLittleEndian::Ipv4PacketLittleEndian(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::parse_packet(UByte* begin, UByte* end)
{
	std::copy(begin, begin + default_ip_bytes, std::back_inserter(header_));

	auto start = begin + default_ip_bytes;
	auto _end = start + (get_ip_header_length() - default_ip_quart_size) * bytes_in_quartet;

	std::copy(start, _end, std::back_inserter(header_));

	next_protocol_ = _end;
}

UByte* QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_next_protocol_byte()
{
	return next_protocol_;
}

QVPN::Core::NetProtocol QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_version() const
{
	return static_cast<NetProtocol>(header_[0] >> 4);
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_header_length() const
{
	return header_[0] & 0xF;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_dscp() const
{
	return header_[1] >> 2;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_ecn() const
{
	return header_[1] & 0x3;
}

UShort QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_total_length() const
{
	UShort first = header_[2] << 8;
	UShort total = first | header_[3];
	return total;
}

UShort QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_id() const
{
	UShort first = header_[4] << 8;
	UShort id = first | header_[5];
	return id;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_flags() const
{
	return header_[6] >> 5;
}

UShort QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_offset() const
{
	UShort first = (header_[6] & 0x1F) << 5;
	UShort offset = first | header_[7];
	return offset;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_ttl() const
{
	return header_[8];
}

QVPN::Core::TransportProtocol QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_protocol() const
{
	return static_cast<TransportProtocol>(header_[9]);
}

UShort QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_checksum() const
{
	UShort first = header_[10] << 8;
	UShort checksum = first | header_[11];
	return checksum;
}

QVPN::Core::IPv4Address QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_source() const
{
	return QVPN::Core::IPv4Address(header_[12], header_[13], header_[14], header_[15]);
	UInt first = header_[12] << 24;
	UInt second = header_[13] << 16;
	UInt third = header_[14] << 8;
	return first | second | third | header_[15];
}

QVPN::Core::IPv4Address QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_dest() const
{
	return QVPN::Core::IPv4Address(header_[16], header_[17], header_[18], header_[19]);
	UInt first = header_[16] << 24;
	UInt second = header_[17] << 16;
	UInt third = header_[18] << 8;
	return first | second | third | header_[19];
}

std::pair<QVPN::Core::DataStructures::Ipv4PacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::Ipv4PacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_additional_header() const
{
	return std::make_pair<>(header_.cbegin() + default_ip_bytes, header_.cend());
}


std::string QVPN::Core::DataStructures::Ipv4PacketLittleEndian::ip_to_friendly_view() const
{
	std::stringstream ss;
	QVPN::Core::IPv4Address source(get_ip_source());
	QVPN::Core::IPv4Address dest(get_ip_dest());

	ss << "IPv4 Package: " << std::endl;
	ss << "Version : " << std::to_string(get_ip_version()) << " Header Length: " << std::to_string(get_ip_header_length()) << " DSCP: " << std::to_string(get_ip_dscp()) << " ECN: " << std::to_string(get_ip_ecn());
	ss << " Total length: " << std::to_string(get_ip_total_length()) << std::endl;
	
	ss << "ID: " << std::to_string(get_ip_id()) << " Flags: " << std::to_string(get_ip_flags()) << " Fragment Offset: " << std::to_string(get_ip_offset()) << std::endl;

	ss << "TTL: " << std::to_string(get_ip_ttl()) << " Protocol: " << std::to_string(get_ip_protocol()) << " Checksum: " << std::to_string(get_ip_checksum()) << std::endl;

	ss << "Source IP: " << source.to_string() << std::endl;

	ss << "Dest IP:" << dest.to_string() << std::endl;

	return ss.str();
}

std::pair<QVPN::Core::DataStructures::Ipv4PacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::Ipv4PacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::to_bytes() const
{
	return std::make_pair<>(header_.cbegin(), header_.cend());
}

std::pair<QVPN::Core::DataStructures::Ipv4PacketLittleEndian::DataIterator_t, QVPN::Core::DataStructures::Ipv4PacketLittleEndian::DataIterator_t> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::to_bytes()
{
	return std::make_pair<>(header_.begin(), header_.end());
}

QVPN::Core::DataStructures::Ipv4PacketLittleEndian::ObjectType QVPN::Core::DataStructures::Ipv4PacketLittleEndian::to_object() const
{
	UByte* start = const_cast<UByte*>(header_.data());
	UByte* end = const_cast<UByte*>(header_.data() + header_.size());
	return ObjectType(start, end);
}

QVPN::Core::DataStructures::Ipv4PacketLittleEndian::ViewType QVPN::Core::DataStructures::Ipv4PacketLittleEndian::to_view() const
{
	UByte* start = const_cast<UByte*>(header_.data());
	UByte* end = const_cast<UByte*>(header_.data() + header_.size());
	return ViewType(start, end);
}

std::string QVPN::Core::DataStructures::Ipv4PacketLittleEndian::to_net_friendly_view() const
{
	return ip_to_friendly_view();
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::set_ip_source(const QVPN::Core::IPv4Address& src)
{
	constexpr auto ip_addr_size = 4;
	constexpr auto ip_start = 12;
	auto temp = src.to_bytes();
	for (auto i = ip_start, j = 0; i < ip_start + ip_addr_size; i++, j++)
	{
		header_[i] = temp.at(j);
	}
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::set_ip_dest(const QVPN::Core::IPv4Address& dst)
{
	constexpr auto ip_addr_size = 4;
	constexpr auto ip_start = 16;
	auto temp = dst.to_bytes();
	for (auto i = ip_start, j = 0; i < ip_start + ip_addr_size; i++, j++)
	{
		header_[i] = temp.at(j);
	}
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::set_ip_checksum(const UShort checksum)
{
	header_[10] = checksum >> 8 & 0xFF;
	header_[11] = checksum & 0xFF;
}

QVPN::Core::NetAddr QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_src_addr() const
{
	return QVPN::Core::NetAddr(header_.data() + 12, header_.data() + 16); // range [12, 16)
}

QVPN::Core::NetAddr QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_dst_addr() const
{
	return QVPN::Core::NetAddr(header_.data() + 16, header_.data() + 20); // range [16, 20)
}

QVPN::Core::NetProtocol QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_protocol_version() const
{
	return static_cast<NetProtocol>(get_ip_version());
}

QVPN::Core::TransportProtocol QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_transport_protocol() const
{
	return static_cast<TransportProtocol>(get_ip_protocol());
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::recalculate_ip_checksum()
{
	unsigned int sum = 0;
	UShort res = 0;
	set_ip_checksum(0);

	for (int i = 0; i < header_.size(); i += 2) {
		UShort temp = header_[i] << 8 | header_[i + 1];
		sum += temp;
	}

	while (sum >> 16)
		sum = ((sum >> 16) + (sum & 0xFFFF));
	res = ~sum;
	set_ip_checksum(res);
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::set_src_addr(const NetAddr& net_addr)
{
	auto bytes = net_addr.to_bytes();
	std::copy(bytes.begin(), bytes.end(), header_.begin() + 12);
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::set_dst_addr(const NetAddr& net_addr)
{
	auto bytes = net_addr.to_bytes();
	std::copy(bytes.begin(), bytes.end(), header_.begin() + 16);
}

QVPN::Core::DataStructures::TcpPacketLittleEndian::TcpPacketLittleEndian(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::parse_packet(UByte* begin, UByte* end)
{
	std::copy(begin, begin + default_tcp_size, std::back_inserter(header_));

	auto start = begin + default_tcp_size;
	auto _end = start + ((get_tcp_header_length() - default_tcp_quart_size) * bytes_in_quartet);

	std::copy(start, _end, std::back_inserter(header_));
	next_protocol_ = _end; 
}

UByte* QVPN::Core::DataStructures::TcpPacketLittleEndian::get_next_protocol_byte()
{
	return next_protocol_;
}


UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_src_port() const
{
	return header_[0] << 8 | header_[1];
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_dst_port() const
{
	return header_[2] << 8 | header_[3];
}

UInt QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_seq_number() const
{
	return header_[4] << 24 | header_[5] << 16 | header_[6] << 8 | header_[7];
}

UInt QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_ack_number() const
{
	return header_[8] << 24 | header_[9] << 16 | header_[10] << 8 | header_[11];
}

UByte QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_header_length() const
{
	return header_[12] >> 4;
}

UByte QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_reserved() const
{
	return header_[12] & 0xF;
}

UByte QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_flags() const
{
	return header_[13];
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_window_size() const
{
	return header_[14] << 8 | header_[15];
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_checksum() const
{
	return header_[16] << 8 | header_[17];
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_urgent_pointer() const
{
	return header_[18] << 8 | header_[19];
}

std::pair<QVPN::Core::DataStructures::TcpPacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TcpPacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_options() const
{
	return std::make_pair<>(header_.cbegin() + default_tcp_size, header_.cend());
}

bool QVPN::Core::DataStructures::TcpPacketLittleEndian::protocol_criteria(UByte protocol) const
{
	return (protocol == QVPN::Core::TransportProtocol::TCP) ? true : false;
}

std::string QVPN::Core::DataStructures::TcpPacketLittleEndian::tcp_to_friendly_view() const
{
	std::stringstream ss;
	ss << "Source port: " << std::to_string(get_tcp_src_port()) << " Dest port: " << std::to_string(get_tcp_dst_port()) << std::endl;
	ss << "Seq: " << std::to_string(get_tcp_seq_number()) << std::endl;
	ss << "Ack: " << std::to_string(get_tcp_ack_number()) << std::endl;
	ss << "Length: " << std::to_string(get_tcp_header_length()) << " Reserverd: " << std::to_string(get_tcp_reserved()) << " Flags: " << std::to_string(get_tcp_flags()) << " Window size: " << std::to_string(get_tcp_window_size()) << std::endl;
	ss << "Checksum: " << std::to_string(get_tcp_checksum()) << " Urgent: " << std::to_string(get_tcp_urgent_pointer()) << std::endl;

	return ss.str();
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_tcp_checksum(UShort checksum)
{
	header_[16] = checksum >> 8 & 0xFF;
	header_[17] = checksum & 0xFF;
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_src_port() const
{
	return get_tcp_src_port();
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_dst_port() const
{
	return get_tcp_dst_port();
}

std::pair<QVPN::Core::DataStructures::TcpPacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TcpPacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TcpPacketLittleEndian::to_bytes() const
{
	return std::make_pair<ConstDataIterator_t, ConstDataIterator_t>(header_.cbegin(), header_.cend());
}

std::pair<QVPN::Core::DataStructures::TcpPacketLittleEndian::DataIterator_t, QVPN::Core::DataStructures::TcpPacketLittleEndian::DataIterator_t> QVPN::Core::DataStructures::TcpPacketLittleEndian::to_bytes()
{
	return std::make_pair<DataIterator_t, DataIterator_t>(header_.begin(), header_.end());
}

QVPN::Core::DataStructures::TcpPacketLittleEndian::ObjectType QVPN::Core::DataStructures::TcpPacketLittleEndian::to_object() const
{
	UByte* start = const_cast<UByte*>(header_.data());
	UByte* end = const_cast<UByte*>(header_.data() + header_.size());
	return ObjectType(start, end);
}

QVPN::Core::DataStructures::TcpPacketLittleEndian::ViewType QVPN::Core::DataStructures::TcpPacketLittleEndian::to_view() const
{
	UByte* start = const_cast<UByte*>(header_.data());
	UByte* end = const_cast<UByte*>(header_.data() + header_.size());
	return ViewType(start, end);
}

std::string QVPN::Core::DataStructures::TcpPacketLittleEndian::to_transport_friendly_view() const
{
	return tcp_to_friendly_view();
}

std::vector<UByte> QVPN::Core::DataStructures::TcpPacketLittleEndian::generate_object_bytes(UShort src_port, UShort dst_port, UInt seq, UInt ack, UByte offset, UByte flags, UShort window_size, UShort urgent)
{
	std::vector<UByte> bytes{};

	bytes.push_back(src_port >> 8 & 0xFF); bytes.push_back(src_port & 0xFF);
	bytes.push_back(dst_port >> 8 & 0xFF); bytes.push_back(dst_port & 0xFF);

	bytes.push_back(seq >> 24 & 0xFF); bytes.push_back(seq >> 16 & 0xFF); bytes.push_back(seq >> 8 & 0xFF); bytes.push_back(seq & 0xFF);
	bytes.push_back(ack >> 24 & 0xFF); bytes.push_back(ack >> 16 & 0xFF); bytes.push_back(ack >> 8 & 0xFF); bytes.push_back(ack & 0xFF);

	bytes.push_back(offset << 4); // + reserved bytes
	bytes.push_back(flags);

	bytes.push_back(window_size >> 8 & 0xFF); bytes.push_back(window_size & 0xFF);

	bytes.push_back(0); bytes.push_back(0); // checksum bytes

	bytes.push_back(urgent >> 8 & 0xFF); bytes.push_back(urgent & 0xFF);

	return bytes;
}

QVPN::Core::DataStructures::TcpPacketLittleEndian::ObjectType QVPN::Core::DataStructures::TcpPacketLittleEndian::generate_object(UShort src_port, UShort dst_port, UInt seq, UInt ack, UByte offset, UByte flags, UShort window_size, UShort urgent)
{
	auto bytes = generate_object_bytes(src_port, dst_port, seq, ack, offset, flags, window_size, urgent);
	return ObjectType(bytes.data(), bytes.data() + bytes.size());
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end)
{
	unsigned int sum = 0;
	UShort res = 0;
	auto [b, e] = pseudo_header.get_by_bytes();


	set_tcp_checksum(0);
	// pseudo-header checksum
	for (auto i = b; i < e; i += 2)
	{
		UShort temp = (static_cast<UShort>(*i << 8 | *(i + 1)));
		sum += temp;
	}


	// tcp header + additional header checksum
	for (int i = 0; i < header_.size(); i += 2) {
		UShort temp = (static_cast<UShort>(header_[i] << 8 | header_[i + 1]));
		sum += temp;
	}

	auto data_size = std::distance(begin, end);
	// data checksum
	for (auto i = begin; i < end; i++) {
		UShort temp;
		if (i + 1 < end)
		{
			temp = (*i << 8 | *(i + 1));
			i++;
		}
		else
		{
			temp = (*i << 8);
		}
		sum += temp;
	}

	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	res = static_cast<UShort>(sum);
	res = (~res);
	set_tcp_checksum(res);
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_transport_length() const
{
	return get_tcp_header_length() * bytes_in_quartet;
}

UInt QVPN::Core::DataStructures::TcpPacketLittleEndian::get_sender_number() const
{
	return get_tcp_seq_number();
}

UInt QVPN::Core::DataStructures::TcpPacketLittleEndian::get_receiver_number() const
{
	return get_tcp_ack_number();
}

UByte QVPN::Core::DataStructures::TcpPacketLittleEndian::get_flags() const
{
	return get_tcp_flags();
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_sender_number(UInt number)
{
	set_tcp_seq_number(number);
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_receiver_number(UInt number)
{
	set_tcp_ack_number(number);
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_flags(UByte flags)
{
	set_tcp_flags(flags);
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_dst_port(UShort port)
{
	header_[2] = static_cast<UByte>(port >> 8 & 0xFF);
	header_[3] = static_cast<UByte>(port & 0xFF);
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_transport_length(UShort length)
{
	header_[4] = static_cast<UByte>(length >> 8 & 0xFF);
	header_[5] = static_cast<UByte>(length & 0xFF);
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_tcp_seq_number(UInt number)
{
	header_[4] = number >> 24 & 0xFF;
	header_[5] = number >> 16 & 0xFF;
	header_[6] = number >> 8 & 0xFF;
	header_[7] = number & 0xFF;
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_tcp_ack_number(UInt number)
{
	header_[8] = number >> 24 & 0xFF;
	header_[9] = number >> 16 & 0xFF;
	header_[10] = number >> 8 & 0xFF;
	header_[11] = number & 0xFF;
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_tcp_flags(UByte flags)
{
	header_[13] = flags;
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_tcp_offset(UByte offset)
{
	header_[12] = offset << 4 | header_[12] & 0x0F;
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_tcp_window(UShort window)
{
	header_[14] = window >> 8 & 0xFF;
	header_[15] = window & 0xFF;
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::set_tcp_urgent(UShort urgent)
{
	header_[18] = urgent >> 8 & 0xFF;
	header_[19] = urgent & 0xFF;
}

QVPN::Core::DataStructures::UdpPacketLittleEndian::UdpPacketLittleEndian(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::UdpPacketLittleEndian::parse_packet(UByte* begin, UByte* end)
{
	//memcpy(header_, begin, default_udp_size);
	std::copy(begin, end, std::back_inserter(header_));
	next_protocol_ = begin + default_udp_size;
}

UByte* QVPN::Core::DataStructures::UdpPacketLittleEndian::get_next_protocol_byte()
{
	return next_protocol_;
}


UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_udp_src_port() const
{
	return header_[0] << 8 | header_[1];
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_udp_dst_port() const
{
	return header_[2] << 8 | header_[3];
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_udp_length() const
{
	return header_[4] << 8 | header_[5];
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_udp_checksum() const
{
	return header_[6] << 8 | header_[7];
}

bool QVPN::Core::DataStructures::UdpPacketLittleEndian::protocol_criteria(UByte protocol) const
{
	return (protocol == QVPN::Core::TransportProtocol::UDP) ? true : false;
}

void QVPN::Core::DataStructures::UdpPacketLittleEndian::set_udp_checksum(UShort checksum)
{
	header_[6] = checksum >> 8 & 0xFF;
	header_[7] = checksum & 0xFF;
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_src_port() const
{
	return get_udp_src_port();
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_dst_port() const
{
	return get_udp_dst_port();
}

std::pair<QVPN::Core::DataStructures::UdpPacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::UdpPacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::UdpPacketLittleEndian::to_bytes() const
{
	return std::make_pair<>(std::begin(header_), std::end(header_));
}

std::pair<QVPN::Core::DataStructures::UdpPacketLittleEndian::DataIterator_t, QVPN::Core::DataStructures::UdpPacketLittleEndian::DataIterator_t> QVPN::Core::DataStructures::UdpPacketLittleEndian::to_bytes()
{
	return std::pair<DataIterator_t, DataIterator_t>(std::begin(header_), std::end(header_));
}

QVPN::Core::DataStructures::UdpPacketLittleEndian::ObjectType QVPN::Core::DataStructures::UdpPacketLittleEndian::to_object() const
{
	UByte* start = const_cast<UByte*>(header_.data());
	UByte* end = const_cast<UByte*>(header_.data() + header_.size());
	return ObjectType(start, end);
}

QVPN::Core::DataStructures::UdpPacketLittleEndian::ViewType QVPN::Core::DataStructures::UdpPacketLittleEndian::to_view() const
{
	UByte* start = const_cast<UByte*>(header_.data());
	UByte* end = const_cast<UByte*>(header_.data() + header_.size());
	return ViewType(start, end);
}

std::string QVPN::Core::DataStructures::UdpPacketLittleEndian::to_transport_friendly_view() const
{
	return to_udp_friendly_view();
}

std::vector<UByte> QVPN::Core::DataStructures::UdpPacketLittleEndian::generate_object_bytes(UShort src_port, UShort dst_port, UShort length)
{
	std::vector<UByte> bytes{};

	bytes.push_back(src_port >> 8 & 0xFF); bytes.push_back(src_port & 0xFF);
	bytes.push_back(dst_port >> 8 & 0xFF); bytes.push_back(dst_port & 0xFF);

	bytes.push_back(length >> 8 & 0xFF); bytes.push_back(length & 0xFF);

	bytes.push_back(0); bytes.push_back(0); // checksum

	return bytes;
}

QVPN::Core::DataStructures::UdpPacketLittleEndian::ObjectType QVPN::Core::DataStructures::UdpPacketLittleEndian::generate_object(UShort src_port, UShort dst_port, UShort length)
{
	auto bytes = generate_object_bytes(src_port, dst_port, length);
	return ObjectType(bytes.data(), bytes.data() + bytes.size());
}

void QVPN::Core::DataStructures::UdpPacketLittleEndian::recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end)
{
	unsigned int sum = 0;
	UShort res = 0;
	auto [b, e] = pseudo_header.get_by_bytes();


	set_udp_checksum(0);
	// pseudo-header checksum
	for (auto i = b; i < e; i += 2)
	{
		UShort temp = (static_cast<UShort>(*i << 8 | *(i + 1)));
		sum += temp;
	}


	// udp header checksum
	for (int i = 0; i < header_.size(); i += 2) {
		UShort temp = (static_cast<UShort>(header_[i] << 8 | header_[i + 1]));
		sum += temp;
	}

	auto data_size = std::distance(begin, end);
	// data checksum
	for (auto i = begin; i < end; i++) {
		UShort temp;
		if (i + 1 < end)
		{
			temp = (*i << 8 | *(i + 1));
			i++;
		}
		else
		{
			temp = (*i << 8);
		}
		sum += temp;
	}

	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	res = static_cast<UShort>(sum);
	res = (~res);
	set_udp_checksum(res);
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_transport_length() const
{
	return get_udp_length() * bytes_in_quartet;
}

UInt QVPN::Core::DataStructures::UdpPacketLittleEndian::get_sender_number() const
{
	return 0;
}

UInt QVPN::Core::DataStructures::UdpPacketLittleEndian::get_receiver_number() const
{
	return 0;
}

UByte QVPN::Core::DataStructures::UdpPacketLittleEndian::get_flags() const
{
	return 0;
}

std::string QVPN::Core::DataStructures::UdpPacketLittleEndian::to_udp_friendly_view() const
{
	std::stringstream ss{};

	ss << "Src port: " << get_udp_src_port(); ss << " Dst port: " << get_udp_dst_port() << std::endl;
	ss << "Length: " << get_udp_length(); ss << "Checksum: " << get_udp_checksum() << std::endl;

	auto str = ss.str();
	return str;
}

void QVPN::Core::DataStructures::UdpPacketLittleEndian::set_sender_number(UInt number)
{
}

void QVPN::Core::DataStructures::UdpPacketLittleEndian::set_receiver_number(UInt number)
{
}

void QVPN::Core::DataStructures::UdpPacketLittleEndian::set_flags(UByte flags)
{
}

void QVPN::Core::DataStructures::UdpPacketLittleEndian::set_dst_port(UShort port)
{
	header_[2] = static_cast<UByte>(port >> 8 & 0xFF);
	header_[3] = static_cast<UByte>(port & 0xFF);
}

void QVPN::Core::DataStructures::UdpPacketLittleEndian::set_transport_length(UShort length)
{
	header_[4] = static_cast<UByte>(length >> 8 & 0xFF);
	header_[5] = static_cast<UByte>(length & 0xFF);
}


QVPN::Core::DataStructures::DataPacketLittleEndian::DataPacketLittleEndian(UByte* begin, UByte* end)
{
	std::copy(begin, end, std::back_inserter(data_));
}

std::pair<QVPN::Core::DataStructures::DataPacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::DataPacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::DataPacketLittleEndian::get_data() const
{
	return std::make_pair<>(data_.cbegin(), data_.cend());
}

std::pair<QVPN::Core::DataStructures::DataPacketLittleEndian::DataIterator_t, QVPN::Core::DataStructures::DataPacketLittleEndian::DataIterator_t> QVPN::Core::DataStructures::DataPacketLittleEndian::get_data()
{
	return std::pair<DataIterator_t, DataIterator_t>(data_.begin(), data_.end());
}

void QVPN::Core::DataStructures::DataPacketLittleEndian::set_data(UByte* begin, UByte* end)
{
}

std::pair<QVPN::Core::DataStructures::DataPacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::DataPacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::DataPacketLittleEndian::to_bytes() const
{
	return std::make_pair<>(data_.cbegin(), data_.cend());
}

std::pair<QVPN::Core::DataStructures::DataPacketLittleEndian::DataIterator_t, QVPN::Core::DataStructures::DataPacketLittleEndian::DataIterator_t> QVPN::Core::DataStructures::DataPacketLittleEndian::to_bytes()
{
	return std::pair<DataIterator_t, DataIterator_t>(data_.begin(), data_.end());
}

QVPN::Core::DataStructures::DataPacketLittleEndian::ObjectType QVPN::Core::DataStructures::DataPacketLittleEndian::to_object() const
{
	UByte* start = const_cast<UByte*>(data_.data());
	UByte* end = const_cast<UByte*>(data_.data() + data_.size());
	return ObjectType(start, end);
}

QVPN::Core::DataStructures::DataPacketLittleEndian::ViewType QVPN::Core::DataStructures::DataPacketLittleEndian::to_view() const
{
	UByte* start = const_cast<UByte*>(data_.data());
	UByte* end = const_cast<UByte*>(data_.data() + data_.size());
	return ViewType(start, end);
}

std::string QVPN::Core::DataStructures::DataPacketLittleEndian::to_data_friendly_view() const
{
	std::stringstream ss{};
	ss << "Data size: " << data_.size() << " bytes";
	auto str = ss.str();
	return str;
}

QVPN::Core::DataStructures::Ipv4PacketView::Ipv4PacketView(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::Ipv4PacketView::parse_packet(UByte* begin, UByte* end)
{
	header_ = begin;
	//std::copy(begin, begin + 20, header_);

	auto start = begin + default_ip_bytes;
	auto _end = start + (get_ip_header_length() - default_ip_quart_size);
	additional_header_ = start;
	add_header_size_ = _end - start;
	next_protocol_ = _end;
}

UByte* QVPN::Core::DataStructures::Ipv4PacketView::get_next_protocol_byte()
{
	return next_protocol_;
}

QVPN::Core::NetProtocol QVPN::Core::DataStructures::Ipv4PacketView::get_ip_version() const
{
	return static_cast<NetProtocol>(header_[0] >> 4);
}

UByte QVPN::Core::DataStructures::Ipv4PacketView::get_ip_header_length() const
{
	return header_[0] & 0xF;
}

UByte QVPN::Core::DataStructures::Ipv4PacketView::get_ip_dscp() const
{
	return header_[1] >> 2;
}

UByte QVPN::Core::DataStructures::Ipv4PacketView::get_ip_ecn() const
{
	return header_[1] & 0x3;
}

UShort QVPN::Core::DataStructures::Ipv4PacketView::get_ip_total_length() const
{
	UShort first = header_[2] << 8;
	UShort total = first | header_[3];
	return total;
}

UShort QVPN::Core::DataStructures::Ipv4PacketView::get_ip_id() const
{
	UShort first = header_[4] << 8;
	UShort id = first | header_[5];
	return id;
}

UByte QVPN::Core::DataStructures::Ipv4PacketView::get_ip_flags() const
{
	return header_[6] >> 5;
}

UShort QVPN::Core::DataStructures::Ipv4PacketView::get_ip_offset() const
{
	UShort first = (header_[6] & 0x1F) << 5;
	UShort offset = first | header_[7];
	return offset;
}

UByte QVPN::Core::DataStructures::Ipv4PacketView::get_ip_ttl() const
{
	return header_[8];
}

QVPN::Core::TransportProtocol QVPN::Core::DataStructures::Ipv4PacketView::get_ip_protocol() const
{
	return static_cast<TransportProtocol>(header_[9]);
}

UShort QVPN::Core::DataStructures::Ipv4PacketView::get_ip_checksum() const
{
	UShort first = header_[10] << 8;
	UShort checksum = first | header_[11];
	return checksum;
}

QVPN::Core::IPv4Address QVPN::Core::DataStructures::Ipv4PacketView::get_ip_source() const
{
	return QVPN::Core::IPv4Address(header_[12], header_[13], header_[14], header_[15]);
	UInt first = header_[12] << 24;
	UInt second = header_[13] << 16;
	UInt third = header_[14] << 8;
	return first | second | third | header_[15];
}

QVPN::Core::IPv4Address QVPN::Core::DataStructures::Ipv4PacketView::get_ip_dest() const
{
	return QVPN::Core::IPv4Address(header_[16], header_[17], header_[18], header_[19]);
	UInt first = header_[16] << 24;
	UInt second = header_[17] << 16;
	UInt third = header_[18] << 8;
	return first | second | third | header_[19];
}

std::pair<QVPN::Core::DataStructures::Ipv4PacketView::ConstDataIterator_t, QVPN::Core::DataStructures::Ipv4PacketView::ConstDataIterator_t> QVPN::Core::DataStructures::Ipv4PacketView::get_ip_additional_header() const
{
	return std::make_pair<>(additional_header_, additional_header_ + add_header_size_);
}


std::string QVPN::Core::DataStructures::Ipv4PacketView::ip_to_friendly_view() const
{
	std::stringstream ss;
	QVPN::Core::IPv4Address source(get_ip_source());
	QVPN::Core::IPv4Address dest(get_ip_dest());

	ss << "IPv4 Package: " << std::endl;
	ss << "Version : " << std::to_string(get_ip_version()) << " Header Length: " << std::to_string(get_ip_header_length()) << " DSCP: " << std::to_string(get_ip_dscp()) << " ECN: " << std::to_string(get_ip_ecn());
	ss << " Total length: " << std::to_string(get_ip_total_length()) << std::endl;

	ss << "ID: " << std::to_string(get_ip_id()) << " Flags: " << std::to_string(get_ip_flags()) << " Fragment Offset: " << std::to_string(get_ip_offset()) << std::endl;

	ss << "TTL: " << std::to_string(get_ip_ttl()) << " Protocol: " << std::to_string(get_ip_protocol()) << " Checksum: " << std::to_string(get_ip_checksum()) << std::endl;

	ss << "Source IP: " << source.to_string() << std::endl;

	ss << "Dest IP:" << dest.to_string() << std::endl;

	return ss.str();
}

std::pair<QVPN::Core::DataStructures::Ipv4PacketView::ConstDataIterator_t, QVPN::Core::DataStructures::Ipv4PacketView::ConstDataIterator_t> QVPN::Core::DataStructures::Ipv4PacketView::to_bytes() const
{
	return std::make_pair<>(header_, additional_header_ + add_header_size_);
}

std::pair<QVPN::Core::DataStructures::Ipv4PacketView::DataIterator_t, QVPN::Core::DataStructures::Ipv4PacketView::DataIterator_t> QVPN::Core::DataStructures::Ipv4PacketView::to_bytes()
{
	return std::make_pair<>(header_, additional_header_ + add_header_size_);
}

QVPN::Core::DataStructures::Ipv4PacketView::ObjectType QVPN::Core::DataStructures::Ipv4PacketView::to_object() const
{
	UByte* start = const_cast<UByte*>(header_);
	UByte* end = const_cast<UByte*>(additional_header_ + add_header_size_);
	return ObjectType(start, end);
}

QVPN::Core::DataStructures::Ipv4PacketView::ViewType QVPN::Core::DataStructures::Ipv4PacketView::to_view() const
{
	UByte* start = const_cast<UByte*>(header_);
	UByte* end = const_cast<UByte*>(additional_header_ + add_header_size_);
	return ViewType(start, end);
}

std::string QVPN::Core::DataStructures::Ipv4PacketView::to_net_friendly_view() const
{
	return ip_to_friendly_view();
}

void QVPN::Core::DataStructures::Ipv4PacketView::set_ip_source(const QVPN::Core::IPv4Address& src)
{
	constexpr auto ip_addr_size = 4;
	constexpr auto ip_start = 12;
	auto temp = src.to_bytes();
	for (auto i = ip_start, j = 0; i < ip_start + ip_addr_size; i++, j++)
	{
		header_[i] = temp.at(j);
	}
}

void QVPN::Core::DataStructures::Ipv4PacketView::set_ip_dest(const QVPN::Core::IPv4Address& dst)
{
	constexpr auto ip_addr_size = 4;
	constexpr auto ip_start = 16;
	auto temp = dst.to_bytes();
	for (auto i = ip_start, j = 0; i < ip_start + ip_addr_size; i++, j++)
	{
		header_[i] = temp.at(j);
	}
}

void QVPN::Core::DataStructures::Ipv4PacketView::set_ip_checksum(const UShort checksum)
{
	header_[10] = checksum >> 8 & 0xFF;
	header_[11] = checksum & 0xFF;
}

QVPN::Core::NetAddr QVPN::Core::DataStructures::Ipv4PacketView::get_src_addr() const
{
	return QVPN::Core::NetAddr(header_ + 12, header_ + 16); // range [12, 16)
}

QVPN::Core::NetAddr QVPN::Core::DataStructures::Ipv4PacketView::get_dst_addr() const
{
	return QVPN::Core::NetAddr(&header_[16], &header_[20]); // range [16, 20)
}

QVPN::Core::NetProtocol QVPN::Core::DataStructures::Ipv4PacketView::get_protocol_version() const
{
	return static_cast<NetProtocol>(get_ip_version());
}

QVPN::Core::TransportProtocol QVPN::Core::DataStructures::Ipv4PacketView::get_transport_protocol() const
{
	return static_cast<TransportProtocol>(get_ip_protocol());
}

void QVPN::Core::DataStructures::Ipv4PacketView::recalculate_ip_checksum()
{
	unsigned int sum = 0;
	UShort res = 0;

	set_ip_checksum(0);

	for (int i = 0; i < ip4_header_size_; i+=2) {
		UShort temp = header_[i] << 8 | header_[i + 1];
		sum += temp;
	}

	for (int i = 0; i < add_header_size_; i++)
	{
		UShort temp = additional_header_[i] << 8 | additional_header_[i + 1];
		sum += temp;
	}

	while (sum >> 16)
		sum = ((sum >> 16) + (sum & 0xFFFF));
	res = ~sum;
	set_ip_checksum(res);
}

void QVPN::Core::DataStructures::Ipv4PacketView::set_src_addr(const NetAddr& net_addr)
{
	auto bytes = net_addr.to_bytes();
	std::copy(bytes.begin(), bytes.end(), header_ + 12);
}

void QVPN::Core::DataStructures::Ipv4PacketView::set_dst_addr(const NetAddr& net_addr)
{
	auto bytes = net_addr.to_bytes();
	std::copy(bytes.begin(), bytes.end(), header_ + 16);
}



QVPN::Core::DataStructures::TcpPacketView::TcpPacketView(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::TcpPacketView::parse_packet(UByte* begin, UByte* end)
{
	constexpr int default_tcp_quart_size = 5;
	constexpr int bytes_in_quartet = 4;
	constexpr int default_tcp_size = default_tcp_quart_size * bytes_in_quartet;
	auto default_end = begin + default_tcp_size;
	tcp_header_ = begin;
	//std::copy(begin, begin + default_tcp_size, tcp_header_);

	auto start = default_end;
	auto _end = start + (get_tcp_header_length() - default_tcp_quart_size) * bytes_in_quartet;
	options_ = start;
	tcp_options_size = _end - start;
	next_protocol_ = _end;
}

UByte* QVPN::Core::DataStructures::TcpPacketView::get_next_protocol_byte()
{
	return next_protocol_;
}


UShort QVPN::Core::DataStructures::TcpPacketView::get_tcp_src_port() const
{
	return tcp_header_[0] << 8 | tcp_header_[1];
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_tcp_dst_port() const
{
	return tcp_header_[2] << 8 | tcp_header_[3];
}

UInt QVPN::Core::DataStructures::TcpPacketView::get_tcp_seq_number() const
{
	return tcp_header_[4] << 24 | tcp_header_[5] << 16 | tcp_header_[6] << 8 | tcp_header_[7];
}

UInt QVPN::Core::DataStructures::TcpPacketView::get_tcp_ack_number() const
{
	return tcp_header_[8] << 24 | tcp_header_[9] << 16 | tcp_header_[10] << 8 | tcp_header_[11];
}

UByte QVPN::Core::DataStructures::TcpPacketView::get_tcp_header_length() const
{
	return tcp_header_[12] >> 4;
}

UByte QVPN::Core::DataStructures::TcpPacketView::get_tcp_reserved() const
{
	return tcp_header_[12] & 0xF;
}

UByte QVPN::Core::DataStructures::TcpPacketView::get_tcp_flags() const
{
	return tcp_header_[13];
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_tcp_window_size() const
{
	return tcp_header_[14] << 8 | tcp_header_[15];
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_tcp_checksum() const
{
	return tcp_header_[16] << 8 | tcp_header_[17];
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_tcp_urgent_pointer() const
{
	return tcp_header_[18] << 8 | tcp_header_[19];
}

std::pair<QVPN::Core::DataStructures::TcpPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::TcpPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::TcpPacketView::get_tcp_options() const
{
	return std::make_pair<>(options_, options_ + tcp_options_size);
}

bool QVPN::Core::DataStructures::TcpPacketView::protocol_criteria(UByte protocol) const
{
	return (protocol == QVPN::Core::TransportProtocol::TCP) ? true : false;
}

std::string QVPN::Core::DataStructures::TcpPacketView::tcp_to_friendly_view() const
{
	std::stringstream ss;
	ss << "Source port: " << std::to_string(get_tcp_src_port()) << " Dest port: " << std::to_string(get_tcp_dst_port()) << std::endl;
	ss << "Seq: " << std::to_string(get_tcp_seq_number()) << std::endl;
	ss << "Ack: " << std::to_string(get_tcp_ack_number()) << std::endl;
	ss << "Length: " << std::to_string(get_tcp_header_length()) << " Reserverd: " << std::to_string(get_tcp_reserved()) << " Flags: " << std::to_string(get_tcp_flags()) << " Window size: " << std::to_string(get_tcp_window_size()) << std::endl;
	ss << "Checksum: " << std::to_string(get_tcp_checksum()) << " Urgent: " << std::to_string(get_tcp_urgent_pointer()) << std::endl;

	return ss.str();
}

std::pair<QVPN::Core::DataStructures::TcpPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::TcpPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::TcpPacketView::get_tcp_header() const
{
	return std::make_pair<>(tcp_header_, tcp_header_ + tcp_header_size);
}

void QVPN::Core::DataStructures::TcpPacketView::set_tcp_checksum(UShort checksum)
{
	tcp_header_[16] = checksum >> 8 & 0xFF;
	tcp_header_[17] = checksum & 0xFF;
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_src_port() const
{
	return get_tcp_src_port();
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_dst_port() const
{
	return get_tcp_dst_port();
}

std::pair< QVPN::Core::DataStructures::TcpPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::TcpPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::TcpPacketView::to_bytes() const
{
	return std::make_pair<>(tcp_header_, options_ + tcp_options_size);
}

std::pair< QVPN::Core::DataStructures::TcpPacketView::DataIterator_t, QVPN::Core::DataStructures::TcpPacketView::DataIterator_t> QVPN::Core::DataStructures::TcpPacketView::to_bytes()
{
	return std::make_pair<>(tcp_header_, options_ + tcp_options_size);
}

QVPN::Core::DataStructures::TcpPacketView::ObjectType QVPN::Core::DataStructures::TcpPacketView::to_object() const
{
	UByte* start = const_cast<UByte*>(tcp_header_);
	UByte* end = const_cast<UByte*>(options_ + tcp_options_size);
	return ObjectType(start, end);
}

QVPN::Core::DataStructures::TcpPacketView::ViewType QVPN::Core::DataStructures::TcpPacketView::to_view() const
{
	UByte* start = const_cast<UByte*>(tcp_header_);
	UByte* end = const_cast<UByte*>(options_ + tcp_options_size);
	return ViewType(start, end);
}

std::string QVPN::Core::DataStructures::TcpPacketView::to_transport_friendly_view() const
{
	return tcp_to_friendly_view();
}

std::vector<UByte> QVPN::Core::DataStructures::TcpPacketView::generate_object_bytes(UShort src_port, UShort dst_port, UInt seq, UInt ack, UByte offset, UByte flags, UShort window_size, UShort urgent)
{
	return TcpPacketLittleEndian::generate_object_bytes(src_port, dst_port, seq, ack, offset, flags, window_size, urgent);
}

QVPN::Core::DataStructures::TcpPacketView::ObjectType QVPN::Core::DataStructures::TcpPacketView::generate_object(UShort src_port, UShort dst_port, UInt seq, UInt ack, UByte offset, UByte flags, UShort window_size, UShort urgent)
{
	return TcpPacketLittleEndian::generate_object(src_port, dst_port, seq, ack, offset, flags, window_size, urgent);
}

void QVPN::Core::DataStructures::TcpPacketView::recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end)
{
	unsigned int sum = 0;
	UShort res = 0;
	auto [b, e] = pseudo_header.get_by_bytes();

	
	set_tcp_checksum(0);
	// pseudo-header checksum
	for (auto i = b; i < e; i+=2)
	{
		UShort temp = (static_cast<UShort>(*i << 8 | *(i + 1)));
		sum += temp;
	}


	// tcp header checksum
	for (int i = 0; i < tcp_header_size; i+=2) {
		UShort temp = (static_cast<UShort>(tcp_header_[i] << 8 | tcp_header_[i + 1]));
		sum += temp;
	}


	// tcp header options checksum
	for (int i = 0; i < tcp_options_size; i+=2) {
		UShort temp = (static_cast<UShort>(options_[i] << 8 | options_[i + 1]));
		sum += temp;
	}

	auto data_size = std::distance(begin, end);
	// data checksum
	for (auto i = begin; i < end; i++) {
		UShort temp;
		if (i + 1 < end)
		{
			temp = (*i << 8 | *(i + 1));
			i++;
		}
		else
		{
			temp = (*i << 8);
		}
		sum += temp;
	}

	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
		
	res = static_cast<UShort>(sum);
	res = (~res);
	set_tcp_checksum(res);
	
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_transport_length() const
{
	return get_tcp_header_length() * bytes_in_quartet;
}

UInt QVPN::Core::DataStructures::TcpPacketView::get_sender_number() const
{
	return get_tcp_seq_number();
}

UInt QVPN::Core::DataStructures::TcpPacketView::get_receiver_number() const
{
	return get_tcp_ack_number();
}

UByte QVPN::Core::DataStructures::TcpPacketView::get_flags() const
{
	return get_tcp_flags();
}

void QVPN::Core::DataStructures::TcpPacketView::set_sender_number(UInt number)
{
	set_tcp_seq_number(number);
}

void QVPN::Core::DataStructures::TcpPacketView::set_receiver_number(UInt number)
{
	set_tcp_ack_number(number);
}

void QVPN::Core::DataStructures::TcpPacketView::set_flags(UByte flags)
{
	set_tcp_flags(flags);
}

void QVPN::Core::DataStructures::TcpPacketView::set_tcp_offset(UByte offset)
{
	tcp_header_[12] = offset << 4 | tcp_header_[12] & 0x0F;
}

void QVPN::Core::DataStructures::TcpPacketView::set_tcp_window(UShort window)
{
	tcp_header_[14] = window >> 8 & 0xFF;
	tcp_header_[15] = window & 0xFF;
}

void QVPN::Core::DataStructures::TcpPacketView::set_tcp_urgent(UShort urgent)
{
	tcp_header_[18] = urgent >> 8 & 0xFF;
	tcp_header_[19] = urgent & 0xFF;
}

void QVPN::Core::DataStructures::TcpPacketView::set_dst_port(UShort port)
{
	tcp_header_[2] = static_cast<UByte>(port >> 8 & 0xFF);
	tcp_header_[3] = static_cast<UByte>(port & 0xFF);
}

void QVPN::Core::DataStructures::TcpPacketView::set_transport_length(UShort length)
{
	tcp_header_[4] = static_cast<UByte>(length >> 8 & 0xFF);
	tcp_header_[5] = static_cast<UByte>(length & 0xFF);
}

void QVPN::Core::DataStructures::TcpPacketView::set_tcp_seq_number(UInt number)
{
	tcp_header_[4] = number >> 24 & 0xFF;
	tcp_header_[5] = number >> 16 & 0xFF;
	tcp_header_[6] = number >> 8 & 0xFF;
	tcp_header_[7] = number & 0xFF;
}

void QVPN::Core::DataStructures::TcpPacketView::set_tcp_ack_number(UInt number)
{
	tcp_header_[8] = number >> 24 & 0xFF;
	tcp_header_[9] = number >> 16 & 0xFF;
	tcp_header_[10] = number >> 8 & 0xFF;
	tcp_header_[11] = number & 0xFF;
}

void QVPN::Core::DataStructures::TcpPacketView::set_tcp_flags(UByte flags)
{
	tcp_header_[13] = flags;
}

QVPN::Core::DataStructures::UdpPacketView::UdpPacketView(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::UdpPacketView::parse_packet(UByte* begin, UByte* end)
{
	constexpr int default_udp_size = 8;
	header_ = begin;
	next_protocol_ = begin + default_udp_size;
}

UByte* QVPN::Core::DataStructures::UdpPacketView::get_next_protocol_byte()
{
	return next_protocol_;
}

UShort QVPN::Core::DataStructures::UdpPacketView::get_udp_src_port() const
{
	return header_[0] << 8 | header_[1];
}

UShort QVPN::Core::DataStructures::UdpPacketView::get_udp_dst_port() const
{
	return header_[2] << 8 | header_[3];
}

UShort QVPN::Core::DataStructures::UdpPacketView::get_udp_length() const
{
	return header_[4] << 8 | header_[5];
}

UShort QVPN::Core::DataStructures::UdpPacketView::get_udp_checksum() const
{
	return header_[6] << 8 | header_[7];
}

bool QVPN::Core::DataStructures::UdpPacketView::protocol_criteria(UByte protocol) const
{
	return (protocol == QVPN::Core::TransportProtocol::UDP) ? true : false;
}

void QVPN::Core::DataStructures::UdpPacketView::set_udp_checksum(UShort checksum)
{
	header_[6] = checksum >> 8 & 0xFF;
	header_[7] = checksum & 0xFF;
}

UShort QVPN::Core::DataStructures::UdpPacketView::get_src_port() const
{
	return get_udp_src_port();
}

UShort QVPN::Core::DataStructures::UdpPacketView::get_dst_port() const
{
	return get_udp_dst_port();
}

std::pair<QVPN::Core::DataStructures::UdpPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::UdpPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::UdpPacketView::to_bytes() const
{
	return std::make_pair<>(header_, header_ + udp_header_size);
}

std::pair<QVPN::Core::DataStructures::UdpPacketView::DataIterator_t, QVPN::Core::DataStructures::UdpPacketView::DataIterator_t> QVPN::Core::DataStructures::UdpPacketView::to_bytes()
{
	return std::make_pair<>(header_, header_ + udp_header_size);
}

QVPN::Core::DataStructures::UdpPacketView::ObjectType QVPN::Core::DataStructures::UdpPacketView::to_object() const
{
	UByte* start = const_cast<UByte*>(header_);
	UByte* end = const_cast<UByte*>(header_ + udp_header_size);
	return ObjectType(start, end);
}

QVPN::Core::DataStructures::UdpPacketView::ViewType QVPN::Core::DataStructures::UdpPacketView::to_view() const
{
	UByte* start = const_cast<UByte*>(header_);
	UByte* end = const_cast<UByte*>(header_ + udp_header_size);
	return ViewType(start, end);
}

std::string QVPN::Core::DataStructures::UdpPacketView::to_transport_friendly_view() const
{
	return to_udp_friendly_view();
}

std::vector<UByte> QVPN::Core::DataStructures::UdpPacketView::generate_object_bytes(UShort src_port, UShort dst_port, UShort length)
{
	return UdpPacketLittleEndian::generate_object_bytes(src_port, dst_port, length);
}

QVPN::Core::DataStructures::UdpPacketView::ObjectType QVPN::Core::DataStructures::UdpPacketView::generate_object(UShort src_port, UShort dst_port, UShort length)
{
	return UdpPacketLittleEndian::generate_object(src_port, dst_port, length);
}

void QVPN::Core::DataStructures::UdpPacketView::recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end)
{
	unsigned int sum = 0;
	UShort res = 0;
	auto [b, e] = pseudo_header.get_by_bytes();


	set_udp_checksum(0);
	// pseudo-header checksum
	for (auto i = b; i < e; i += 2)
	{
		UShort temp = (static_cast<UShort>(*i << 8 | *(i + 1)));
		sum += temp;
	}


	// udp header checksum
	for (int i = 0; i < udp_header_size; i += 2) {
		UShort temp = (static_cast<UShort>(header_[i] << 8 | header_[i + 1]));
		sum += temp;
	}

	auto data_size = std::distance(begin, end);
	// data checksum
	for (auto i = begin; i < end; i++) {
		UShort temp;
		if (i + 1 < end)
		{
			temp = (*i << 8 | *(i + 1));
			i++;
		}
		else
		{
			temp = (*i << 8);
		}
		sum += temp;
	}

	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	res = static_cast<UShort>(sum);
	res = (~res);
	set_udp_checksum(res);
}

UShort QVPN::Core::DataStructures::UdpPacketView::get_transport_length() const
{
	return get_udp_length() * bytes_in_quartet;
}

UInt QVPN::Core::DataStructures::UdpPacketView::get_sender_number() const
{
	return 0;
}

UInt QVPN::Core::DataStructures::UdpPacketView::get_receiver_number() const
{
	return 0;
}

UByte QVPN::Core::DataStructures::UdpPacketView::get_flags() const
{
	return 0;
}

std::string QVPN::Core::DataStructures::UdpPacketView::to_udp_friendly_view() const
{
	std::stringstream ss{};

	ss << "Src port: " << get_udp_src_port(); ss << " Dst port: " << get_udp_dst_port() << std::endl;
	ss << "Length: " << get_udp_length(); ss << "Checksum: " << get_udp_checksum() << std::endl;

	auto str = ss.str();
	return str;
}

void QVPN::Core::DataStructures::UdpPacketView::set_sender_number(UInt number)
{
}

void QVPN::Core::DataStructures::UdpPacketView::set_receiver_number(UInt number)
{
}

void QVPN::Core::DataStructures::UdpPacketView::set_flags(UByte flags)
{
}

void QVPN::Core::DataStructures::UdpPacketView::set_dst_port(UShort port)
{
	header_[2] = static_cast<UByte>(port >> 8 & 0xFF);
	header_[3] = static_cast<UByte>(port & 0xFF);
}

void QVPN::Core::DataStructures::UdpPacketView::set_transport_length(UShort length)
{
	header_[4] = static_cast<UByte>(length >> 8 & 0xFF);
	header_[5] = static_cast<UByte>(length & 0xFF);
}


QVPN::Core::DataStructures::DataPacketView::DataPacketView(UByte* begin, UByte* end)
{
	data_ = begin;
	//std::copy(begin, begin + 5, data_);
	data_size_ = end - begin;
}

std::pair<QVPN::Core::DataStructures::DataPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::DataPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::DataPacketView::get_data() const
{
	return std::make_pair<>(data_, data_ + data_size_);
}

std::pair<QVPN::Core::DataStructures::DataPacketView::DataIterator_t, QVPN::Core::DataStructures::DataPacketView::DataIterator_t> QVPN::Core::DataStructures::DataPacketView::get_data()
{
	auto data_end = data_ + data_size_;
	return std::pair<DataIterator_t, DataIterator_t>(data_, data_end);
}

void QVPN::Core::DataStructures::DataPacketView::set_data(UByte* begin, UByte* end)
{
	std::copy(begin, end, data_);
	//data_ = begin;
	//data_size_ = end - begin;
}

std::pair<QVPN::Core::DataStructures::DataPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::DataPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::DataPacketView::to_bytes() const
{
	return std::make_pair<>(data_, data_ + data_size_);
}

std::pair<QVPN::Core::DataStructures::DataPacketView::DataIterator_t, QVPN::Core::DataStructures::DataPacketView::DataIterator_t> QVPN::Core::DataStructures::DataPacketView::to_bytes()
{
	auto data_end = data_ + data_size_;
	return std::pair<DataIterator_t, DataIterator_t>(data_, data_end);
}

QVPN::Core::DataStructures::DataPacketView::ObjectType QVPN::Core::DataStructures::DataPacketView::to_object() const
{
	UByte* start = const_cast<UByte*>(data_);
	UByte* end = const_cast<UByte*>(data_ + data_size_);
	return ObjectType(start, end);
}

QVPN::Core::DataStructures::DataPacketView::ViewType QVPN::Core::DataStructures::DataPacketView::to_view() const
{
	UByte* start = const_cast<UByte*>(data_);
	UByte* end = const_cast<UByte*>(data_ + data_size_);
	return ViewType(start, end);
}

std::string QVPN::Core::DataStructures::DataPacketView::to_data_friendly_view() const
{
	std::stringstream ss{};
	ss << "Data size: " << data_size_ << " bytes";
	auto str = ss.str();
	return str;
}

QVPN::Core::DataStructures::TransportIpv4PseudoHeader::TransportIpv4PseudoHeader(UInt src, UInt dst, UByte protocol, UShort length)
{
	constexpr auto addr_size = sizeof(src);
	constexpr auto proto_size = sizeof(protocol);
	constexpr auto length_size = sizeof(length);
	
	/*
	ph_src = src;
	ph_dst = dst;
	ph_zero = 0;
	ph_protocol = protocol;
	ph_length = length;
	*/
	
	// src
	data[3] = src & 0xFF;
	data[2] = src >> 8 & 0xFF;
	data[1] = src >> 16 & 0xFF;
	data[0] = src >> 24 & 0xFF;

	//dst
	data[7] = dst & 0xFF;
	data[6] = dst >> 8 & 0xFF;
	data[5] = dst >> 16 & 0xFF;
	data[4] = dst >> 24 & 0xFF;

	//zero
	data[8] = 0;

	// proto
	data[9] = protocol;

	//length
	data[11] = length & 0xFF;
	data[10] = length >> 8 & 0xFF;
	
	/*
	std::memcpy(data, &src, addr_size);
	std::memcpy(data + addr_size, &dst, addr_size);
	data[8] = 0;
	data[9] = protocol;
	std::memcpy(&data[10], &length, length_size);
	*/
}

QVPN::Core::DataStructures::TransportIpv4PseudoHeader::TransportIpv4PseudoHeader(IPv4Address& src, IPv4Address& dst, UByte protocol, UShort length)
{
	auto src_b = src.to_bytes();
	auto dst_b = dst.to_bytes();

	std::copy(std::begin(src_b), std::end(src_b), std::begin(data));
	std::copy(std::begin(dst_b), std::end(dst_b), data + src_b.size());

	// proto
	data[9] = protocol;

	//length
	data[11] = length & 0xFF;
	data[10] = length >> 8 & 0xFF;
}

std::pair<const UByte*, const UByte*> QVPN::Core::DataStructures::TransportIpv4PseudoHeader::get_by_bytes() const
{
	return std::make_pair<>(std::begin(data), std::end(data));
}

QVPN::Core::DataStructures::TransportIpv4PseudoHeaderTypesBuffer QVPN::Core::DataStructures::TransportIpv4PseudoHeader::get_by_types() const
{
	UInt src, dst;
	UByte protocol;
	UShort length;
	UByte zero = 0;
	constexpr auto addr_size = sizeof(src);
	constexpr auto proto_size = sizeof(protocol);
	constexpr auto length_size = sizeof(length);
	std::memcpy(&src, data, addr_size);
	std::memcpy(&dst, data + addr_size, addr_size);
	protocol = data[9];
	std::memcpy(&length, &data[10], length_size);
	return TransportIpv4PseudoHeaderTypesBuffer({src, dst, zero, protocol, length});
}

// Http Request LE


std::string_view QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::to_string_view() const
{
	return std::string_view(reinterpret_cast<const char*>(data_.data()), data_.size());
}

std::pair<QVPN::Core::DataStructures::HttpVersion, std::string> QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_version() const
{
	constexpr std::string_view version_template = "HTTP/";
	std::string_view req = to_string_view();
	auto ver = HttpTools::get_http_header_line(req, version_template);
	return std::make_pair<>(HttpTools::get_http_version_by_string(ver), std::move(std::string(ver)));
}

std::string QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_request() const
{
	return std::string(reinterpret_cast<const char*>(data_.data()), data_.size());
}

std::string QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_request_header() const
{
	auto [b, e] = get_http_request_header_bytes();
	auto size = std::distance(b, e);
	return std::string(reinterpret_cast<const char*>(data_.data()), size);
}

std::string QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_request_body() const
{
	auto [b, e] = get_http_request_header_bytes();
	auto start = std::distance(b, e);
	auto size = std::distance(e, data_.end());
	return std::string(reinterpret_cast<const char*>(data_.data() + start), size);
}

std::pair<QVPN::Core::DataStructures::HttpRequestType, std::string> QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_request_type() const
{
	std::string_view req = to_string_view();
	auto type_end = req.find(' ');
	std::string req_type(req.substr(0, type_end));
	return std::make_pair<>(HttpTools::get_request_type_by_string(req_type), std::move(req_type));
}

std::string QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_request_host() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view host = "Host:";
	return std::string(HttpTools::get_http_header_line(req, host));
}

std::pair<QVPN::Core::DataStructures::HttpConnectionType, std::string> QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_request_connection_type() const
{
	constexpr std::string_view con_template = "Connection:";
	std::string_view req = to_string_view();
	auto con_type = HttpTools::get_http_header_line(req, con_template);
	return std::make_pair<>(HttpTools::get_http_connection_type_by_string(con_type), std::move(std::string(con_type)));
}

std::pair<QVPN::Core::DataStructures::HttpUserAgent, std::string> QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_request_user_agent() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view user_agent = "User-Agent:";
	auto val = HttpTools::get_http_header_line(req, user_agent);
	return std::make_pair<>(HttpUserAgent::UKNOWN, std::move(std::string(val)));
}

std::pair<QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_request_header_bytes() const
{
	auto pos = HttpTools::find_http_header_end(data_.begin(), data_.end());
	return std::make_pair<ConstDataIterator_t, ConstDataIterator_t>(data_.begin(), data_.begin() + pos);
}

std::pair<QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::get_http_request_body_bytes() const
{
	auto pos = HttpTools::find_http_header_end(data_.begin(), data_.end());
	return std::make_pair<ConstDataIterator_t, ConstDataIterator_t>(data_.begin() + pos, data_.end());
}

std::pair<QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketRequestLittleEndian::to_bytes() const
{
	return std::make_pair<>(data_.begin(), data_.end());
}

/// Http Request View

std::string_view QVPN::Core::DataStructures::Http1PacketRequestView::to_string_view() const
{
	return std::string_view(reinterpret_cast<const char*>(data_), data_size_);
}

std::pair<QVPN::Core::DataStructures::HttpVersion, std::string> QVPN::Core::DataStructures::Http1PacketRequestView::get_http_version() const
{
	constexpr std::string_view version_template = "HTTP/";
	std::string_view req = to_string_view();
	auto ver = HttpTools::get_http_header_line(req, version_template);
	return std::make_pair<>(HttpTools::get_http_version_by_string(ver), std::move(std::string(ver)));
}

std::string QVPN::Core::DataStructures::Http1PacketRequestView::get_http_request() const
{
	return std::string(reinterpret_cast<const char*>(data_), data_size_);
}

std::string QVPN::Core::DataStructures::Http1PacketRequestView::get_http_request_header() const
{
	auto [b, e] = get_http_request_header_bytes();
	auto size = std::distance(b, e);
	return std::string(reinterpret_cast<const char*>(data_), size);
}

std::string QVPN::Core::DataStructures::Http1PacketRequestView::get_http_request_body() const
{
	auto [b, e] = get_http_request_header_bytes();
	auto start = std::distance(b, e);
	auto size = data_ + data_size_ - e;
	return std::string(reinterpret_cast<const char*>(data_ + start), size);
}

std::pair<QVPN::Core::DataStructures::HttpRequestType, std::string> QVPN::Core::DataStructures::Http1PacketRequestView::get_http_request_type() const
{
	std::string_view req = to_string_view();
	auto type_end = req.find(' ');
	std::string req_type(req.substr(0, type_end));
	return std::make_pair<>(HttpTools::get_request_type_by_string(req_type), std::move(req_type));
}

std::string QVPN::Core::DataStructures::Http1PacketRequestView::get_http_request_host() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view host = "Host:";
	return std::string(HttpTools::get_http_header_line(req, host));
}

std::pair<QVPN::Core::DataStructures::HttpConnectionType, std::string> QVPN::Core::DataStructures::Http1PacketRequestView::get_http_request_connection_type() const
{
	constexpr std::string_view con_template = "Connection:";
	std::string_view req = to_string_view();
	auto con_type = HttpTools::get_http_header_line(req, con_template);
	return std::make_pair<>(HttpTools::get_http_connection_type_by_string(con_type), std::move(std::string(con_type)));
}

std::pair<QVPN::Core::DataStructures::HttpUserAgent, std::string> QVPN::Core::DataStructures::Http1PacketRequestView::get_http_request_user_agent() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view user_agent = "User-Agent:";
	auto val = HttpTools::get_http_header_line(req, user_agent);
	return std::make_pair<>(HttpUserAgent::UKNOWN, std::move(std::string(val)));
}

std::pair<QVPN::Core::DataStructures::Http1PacketRequestView::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketRequestView::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketRequestView::get_http_request_header_bytes() const
{
	auto pos = HttpTools::find_http_header_end(data_, data_ + data_size_);
	return std::make_pair<>(data_, data_ + pos);
}

std::pair<QVPN::Core::DataStructures::Http1PacketRequestView::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketRequestView::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketRequestView::get_http_request_body_bytes() const
{
	auto pos = HttpTools::find_http_header_end(data_, data_ + data_size_);
	return std::make_pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + pos, data_ + data_size_);
}

std::pair<QVPN::Core::DataStructures::Http1PacketRequestView::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketRequestView::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketRequestView::to_bytes() const
{
	return std::make_pair<>(data_, data_ + data_size_);
}


/// Http Response LE

std::string_view QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::to_string_view() const
{
	return std::string_view(reinterpret_cast<const char*>(data_.data()), data_.size());
}

std::pair<QVPN::Core::DataStructures::HttpVersion, std::string> QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_version() const
{
	constexpr std::string_view version_template = "HTTP/";
	std::string_view req = to_string_view();
	auto ver = HttpTools::get_http_header_block(req, version_template);
	return std::make_pair<>(HttpTools::get_http_version_by_string(ver), std::move(std::string(ver)));
}

std::string QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response() const
{
	return std::string(reinterpret_cast<const char*>(data_.data()), data_.size());
}

std::string QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response_header() const
{
	auto [b, e] = get_http_response_header_bytes();
	auto size = std::distance(b, e);
	return std::string(reinterpret_cast<const char*>(data_.data()), size);
}

std::string QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response_body() const
{
	auto [b, e] = get_http_response_header_bytes();
	auto start = std::distance(b, e);
	auto size = std::distance(e, data_.end());
	return std::string(reinterpret_cast<const char*>(data_.data() + start), size);
}

std::pair<QVPN::Core::DataStructures::HttpResponseStatus, std::string> QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response_status() const
{
	std::string_view req = to_string_view();
	auto start = req.find(' ') + 1; // first space + next symbol = response code // example HTTP/1.0 200 OK
	auto end = req.find(' ', start);
	auto size = end - start;
	std::string status(req.substr(start, size));
	return std::make_pair<>(HttpTools::get_http_status_by_string(status), std::move(status));
}

std::pair<QVPN::Core::DataStructures::HttpContentType, std::string> QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response_content_type() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view content_template = "Content-Type:";
	auto ctype_line = HttpTools::get_http_header_line(req, content_template);
	auto ctype_end = ctype_line.find(";");
	std::string_view val = ctype_line.substr(0, ctype_end);
	return std::make_pair<>(HttpTools::get_http_content_type_by_string(val), std::move(std::string(val)));
}

std::pair<QVPN::Core::DataStructures::QVPNCharset, std::string> QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response_charset() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view charset_template = "charset=";
	auto charset = HttpTools::get_http_header_line(req, charset_template);
	return std::make_pair<>(HttpTools::get_http_charset_by_string(charset), std::move(std::string(charset)));
}

UInt QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response_content_length() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view content_length_template = "Content-Length:";
	auto length = HttpTools::get_http_header_line(req, content_length_template);
	return static_cast<UInt>(std::stoi(std::string(length)));
}

std::string QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response_server() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view server_template = "Server:";
	auto server = HttpTools::get_http_header_line(req, server_template);
	return std::string(server);
}

std::pair<QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response_header_bytes() const
{
	auto pos = HttpTools::find_http_header_end(data_.begin(), data_.end());
	return std::make_pair<>(data_.begin(), data_.begin() + pos);
}

std::pair<QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::get_http_response_body_bytes() const
{
	auto pos = HttpTools::find_http_header_end(data_.begin(), data_.end());
	return std::make_pair<>(data_.begin() + pos, data_.end());
}


std::pair<QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketResponseLittleEndian::to_bytes() const
{
	return std::make_pair<>(data_.begin(), data_.end());
}

/// Http Response View

std::string_view QVPN::Core::DataStructures::Http1PacketResponseView::to_string_view() const
{
	return std::string_view(reinterpret_cast<const char*>(data_), data_size_);
}

std::pair<QVPN::Core::DataStructures::HttpVersion, std::string> QVPN::Core::DataStructures::Http1PacketResponseView::get_http_version() const
{
	constexpr std::string_view version_template = "HTTP/";
	std::string_view req = to_string_view();
	auto ver = HttpTools::get_http_header_block(req, version_template);
	return std::make_pair<>(HttpTools::get_http_version_by_string(ver), std::move(std::string(ver)));
}

std::string QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response() const
{
	return std::string(reinterpret_cast<const char*>(data_), data_size_);
}

std::string QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response_header() const
{
	auto [b, e] = get_http_response_header_bytes();
	auto size = std::distance(b, e);
	return std::string(reinterpret_cast<const char*>(data_), size);
}

std::string QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response_body() const
{
	auto [b, e] = get_http_response_header_bytes();
	auto start = std::distance(b, e);
	const UByte* end = data_ + data_size_;
	auto size = std::distance(e, end);
	return std::string(reinterpret_cast<const char*>(data_ + start), size);
}

std::pair<QVPN::Core::DataStructures::HttpResponseStatus, std::string> QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response_status() const
{
	std::string_view req = to_string_view();
	auto start = req.find(' ') + 1; // first space + next symbol = response code // example HTTP/1.0 200 OK
	auto end = req.find(' ', start);
	auto size = end - start;
	std::string status(req.substr(start, size));
	return std::make_pair<>(HttpTools::get_http_status_by_string(status), std::move(status));
}

std::pair<QVPN::Core::DataStructures::HttpContentType, std::string> QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response_content_type() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view content_template = "Content-Type:";
	auto ctype_line = HttpTools::get_http_header_line(req, content_template);
	auto ctype_end = ctype_line.find(";");
	std::string_view val = ctype_line.substr(0, ctype_end);
	return std::make_pair<>(HttpTools::get_http_content_type_by_string(val), std::move(std::string(val)));
}

std::pair<QVPN::Core::DataStructures::QVPNCharset, std::string> QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response_charset() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view charset_template = "charset=";
	auto charset = HttpTools::get_http_header_line(req, charset_template);
	return std::make_pair<>(HttpTools::get_http_charset_by_string(charset), std::move(std::string(charset)));
}

UInt QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response_content_length() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view content_length_template = "Content-Length:";
	auto length = HttpTools::get_http_header_line(req, content_length_template);
	return static_cast<UInt>(std::stoi(std::string(length)));
}

std::string QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response_server() const
{
	std::string_view req = to_string_view();
	constexpr std::string_view server_template = "Server:";
	auto server = HttpTools::get_http_header_line(req, server_template);
	return std::string(server);
}

std::pair<QVPN::Core::DataStructures::Http1PacketResponseView::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketResponseView::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response_header_bytes() const
{
	auto pos = HttpTools::find_http_header_end(data_, data_ + data_size_);
	return std::make_pair<>(data_, data_ + pos);
}

std::pair<QVPN::Core::DataStructures::Http1PacketResponseView::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketResponseView::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketResponseView::get_http_response_body_bytes() const
{
	auto pos = HttpTools::find_http_header_end(data_, data_ + data_size_);
	return std::make_pair<>(data_ + pos, data_ + data_size_);
}

std::pair<QVPN::Core::DataStructures::Http1PacketResponseView::ConstDataIterator_t, QVPN::Core::DataStructures::Http1PacketResponseView::ConstDataIterator_t> QVPN::Core::DataStructures::Http1PacketResponseView::to_bytes() const
{
	return std::make_pair<>(data_, data_ + data_size_);
}


// TLS


// TLS Fields 


// TLS Random LE

std::array<UByte, 32> QVPN::Core::DataStructures::TLSRandomLittleEndian::generate_object_bytes()
{
	constexpr UByte length = 32;
	auto obj_bytes = TLSTools::array32_bytes_generator<UByte>(length, 4);
	int time = std::time(nullptr);
	obj_bytes[0] = time >> 24 & 0xFF;
	obj_bytes[1] = time >> 16 & 0xFF;
	obj_bytes[2] = time >> 8 & 0xFF;
	obj_bytes[3] = time & 0xFF;
	return obj_bytes;
}

QVPN::Core::DataStructures::TLSRandomLittleEndian QVPN::Core::DataStructures::TLSRandomLittleEndian::generate_object()
{
	auto obj_bytes = generate_object_bytes();
	return TLSRandomLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSRandomLittleEndian::get_tls_random_full_length() const
{
	return 32;
}

UInt QVPN::Core::DataStructures::TLSRandomLittleEndian::get_tls_unix_time() const
{
	return random_bytes_[0] << 24 | random_bytes_[1] << 16 | random_bytes_[2] << 8 | random_bytes_[3];
}

std::pair<QVPN::Core::DataStructures::TLSRandomLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSRandomLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSRandomLittleEndian::get_tls_random_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(random_bytes_.cbegin() + 4, random_bytes_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSRandomLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSRandomLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSRandomLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(random_bytes_.cbegin(), random_bytes_.cend());
}


// TLS Random View

std::array<UByte, 32> QVPN::Core::DataStructures::TLSRandomView::generate_object_bytes()
{
	return TLSRandomLittleEndian::generate_object_bytes();
}

QVPN::Core::DataStructures::TLSRandomLittleEndian QVPN::Core::DataStructures::TLSRandomView::generate_object()
{
	return TLSRandomLittleEndian::generate_object();
}

UShort QVPN::Core::DataStructures::TLSRandomView::get_tls_random_full_length() const
{
	return 32;
}

UInt QVPN::Core::DataStructures::TLSRandomView::get_tls_unix_time() const
{
	return static_cast<UInt>(random_bytes_[0] << 24 | random_bytes_[1] << 16 | random_bytes_[2] << 8 | random_bytes_[3]);
}

std::pair<QVPN::Core::DataStructures::TLSRandomView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSRandomView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSRandomView::get_tls_random_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(random_bytes_ + 4, random_bytes_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSRandomView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSRandomView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSRandomView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(random_bytes_, random_bytes_ + size_);
}

// TLS SessionID LE

std::vector<UByte> QVPN::Core::DataStructures::TLSSessionIDLittleEndian::generate_object_bytes(UByte length)
{
	auto full_length = length + sizeof(length);
	auto obj_bytes = TLSTools::vector_bytes_generator<UByte>(full_length, 1);
	obj_bytes[0] = length;
	return obj_bytes;
}

QVPN::Core::DataStructures::TLSSessionIDLittleEndian QVPN::Core::DataStructures::TLSSessionIDLittleEndian::generate_object(UByte length)
{
	auto obj_bytes = generate_object_bytes(length);
	return TLSSessionIDLittleEndian(obj_bytes.begin(), obj_bytes.end());
}


UShort QVPN::Core::DataStructures::TLSSessionIDLittleEndian::get_tls_id_full_length() const
{
	return get_tls_id_length() + 1;
}

UByte QVPN::Core::DataStructures::TLSSessionIDLittleEndian::get_tls_id_length() const
{
	return id_[0];
}

std::pair<QVPN::Core::DataStructures::TLSSessionIDLittleEndian::DataIterator_t, QVPN::Core::DataStructures::TLSSessionIDLittleEndian::DataIterator_t> QVPN::Core::DataStructures::TLSSessionIDLittleEndian::get_tls_id()
{
	return std::pair<DataIterator_t, DataIterator_t>(id_.begin() + 1, id_.end());
}

std::pair<QVPN::Core::DataStructures::TLSSessionIDLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSessionIDLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSessionIDLittleEndian::get_tls_id() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(id_.cbegin() + 1, id_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSSessionIDLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSessionIDLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSessionIDLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(id_.cbegin(), id_.cend());
}


// TLS SessionID View


std::vector<UByte> QVPN::Core::DataStructures::TLSSessionIDView::generate_object_bytes(UByte length)
{
	return TLSSessionIDLittleEndian::generate_object_bytes(length);
}

QVPN::Core::DataStructures::TLSSessionIDLittleEndian QVPN::Core::DataStructures::TLSSessionIDView::generate_object(UByte length)
{
	return TLSSessionIDLittleEndian::generate_object(length);
}

UInt QVPN::Core::DataStructures::TLSSessionIDView::get_tls_id_full_length() const
{
	return get_tls_id_length() + 1;
}

UByte QVPN::Core::DataStructures::TLSSessionIDView::get_tls_id_length() const
{
	return data_[0];
}

std::pair<QVPN::Core::DataStructures::TLSSessionIDView::DataIterator_t, QVPN::Core::DataStructures::TLSSessionIDView::DataIterator_t> QVPN::Core::DataStructures::TLSSessionIDView::get_tls_id()
{
	return std::pair<DataIterator_t, DataIterator_t>(data_ + 1, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSSessionIDView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSessionIDView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSessionIDView::get_tls_id() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 1, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSSessionIDView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSessionIDView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSessionIDView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS Extension LE


UShort QVPN::Core::DataStructures::TLSExtensionLittleEndian::get_tls_ext_full_length() const
{
	return get_tls_ext_length() + 4;
}

QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSExtensionLittleEndian::get_tls_ext_type() const
{
	return static_cast<TLSExtensionType>(data_[0] << 8 | data_[1]);
}

UShort QVPN::Core::DataStructures::TLSExtensionLittleEndian::get_tls_ext_length() const
{
	return static_cast<UShort>(data_[2] << 8 | data_[3]);
}

std::pair<QVPN::Core::DataStructures::TLSExtensionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSExtensionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSExtensionLittleEndian::get_tls_ext_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin() + 4, data_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSExtensionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSExtensionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSExtensionLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin(), data_.cend());
}


// TLS Extension View


UShort QVPN::Core::DataStructures::TLSExtensionView::get_tls_ext_full_length() const
{
	return get_tls_ext_length() + 4;
}

QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSExtensionView::get_tls_ext_type() const
{
	return static_cast<TLSExtensionType>(data_[0] << 8 | data_[1]);
}

UShort QVPN::Core::DataStructures::TLSExtensionView::get_tls_ext_length() const
{
	return static_cast<UShort>(data_[2] << 8 | data_[3]);
}

std::pair<QVPN::Core::DataStructures::TLSExtensionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSExtensionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSExtensionView::get_tls_ext_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 4, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSExtensionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSExtensionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSExtensionView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS SupVerExt LE


QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::get_extension_type()
{
	return TLSExtensionType::SUPPORTED_VERSIONS;
}

std::vector<UByte> QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::generate_object_bytes(std::pair<SupVerIter, SupVerIter> versions)
{
	std::vector<UByte> obj_bytes;
	UByte list_length = 0;
	
	for (auto& i = versions.first; i < versions.second; i++)
	{
		auto ver = TLSSupportedVersionsEntryLittleEndian::generate_object_bytes(2, *i);
		obj_bytes.push_back(ver[0]);
		obj_bytes.push_back(ver[1]);
		list_length += ver.size();
	}

	obj_bytes.insert(obj_bytes.begin(), list_length & 0xFF);
	return obj_bytes;
}

QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::generate_object(std::pair<SupVerIter, SupVerIter> versions)
{
	auto obj_bytes = generate_object_bytes(versions);
	return TLSSupportedVersionsClientHelloExtensionLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::get_tls_versions_full_length() const
{
	return get_tls_versions_length() + 1;
}

UByte QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::get_tls_versions_length() const
{
	return static_cast<UShort>(versions_[0]);
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::get_tls_supported_versions() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(versions_.cbegin() + 1, versions_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(versions_.cbegin(), versions_.cend());
}


// TLS SupVer Ext View


QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::get_extension_type()
{
	return TLSExtensionType::SUPPORTED_VERSIONS;
}

std::vector<UByte> QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::generate_object_bytes(std::pair<SupVerIter, SupVerIter> versions)
{
	return TLSSupportedVersionsClientHelloExtensionLittleEndian::generate_object_bytes(std::move(versions));
}

QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionLittleEndian QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::generate_object(std::pair<SupVerIter, SupVerIter> versions)
{
	return TLSSupportedVersionsClientHelloExtensionLittleEndian::generate_object(std::move(versions));
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::get_tls_versions_full_length() const
{
	return get_tls_versions_length() + 1;
}

UByte QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::get_tls_versions_length() const
{
	return static_cast<UByte>(data_[0]);
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::get_tls_supported_versions() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 1, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsClientHelloExtensionView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS Key Share Entry LE


std::vector<UByte> QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::generate_object_bytes(UShort length, TLSKeyTypes key_type)
{
	auto obj_bytes = TLSTools::vector_bytes_generator<UShort>(length + sizeof(length) + sizeof(TLSKeyTypes), 4);
	obj_bytes[0] = key_type >> 8 & 0xFF;
	obj_bytes[1] = key_type & 0xFF;
	obj_bytes[2] = length >> 8 & 0xFF;
	obj_bytes[3] = length & 0xFF;
	return obj_bytes;
}

QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::generate_object(UShort length, TLSKeyTypes key_type)
{
	auto obj_bytes = generate_object_bytes(length, key_type);
	return TLSKeyShareEntryLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::get_tls_key_share_entry_full_length() const
{
	return get_tls_key_share_entry_length() + 4;
}

UShort QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::get_tls_key_share_entry_length() const
{
	return static_cast<UShort>(key_exchange_[2] << 8 | key_exchange_[3]);
}

UShort QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::get_tls_key_share_key_type() const
{
	return static_cast<UShort>(key_exchange_[0] << 8 | key_exchange_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::get_tls_key_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(key_exchange_.cbegin() + 4, key_exchange_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(key_exchange_.cbegin(), key_exchange_.cend());
}


// TLS Key Share Entry View


std::vector<UByte> QVPN::Core::DataStructures::TLSKeyShareEntryView::generate_object_bytes(UShort length, TLSKeyTypes key_type)
{
	return TLSKeyShareEntryLittleEndian::generate_object_bytes(length, key_type);
}

QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian QVPN::Core::DataStructures::TLSKeyShareEntryView::generate_object(UShort length, TLSKeyTypes key_type)
{
	return TLSKeyShareEntryLittleEndian::generate_object(length, key_type);
}

UShort QVPN::Core::DataStructures::TLSKeyShareEntryView::get_tls_key_share_entry_full_length() const
{
	return get_tls_key_share_entry_length() + 4;
}

UShort QVPN::Core::DataStructures::TLSKeyShareEntryView::get_tls_key_share_key_type() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

UShort QVPN::Core::DataStructures::TLSKeyShareEntryView::get_tls_key_share_entry_length() const
{
	return static_cast<UShort>(data_[2] << 8 | data_[3]);
}

std::pair<QVPN::Core::DataStructures::TLSKeyShareEntryView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSKeyShareEntryView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSKeyShareEntryView::get_tls_key_exchange() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 4, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSKeyShareEntryView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSKeyShareEntryView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSKeyShareEntryView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS Key Share Client Hello LE


QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::get_extension_type()
{
	return TLSExtensionType::KEY_SHARE;
}

std::vector<UByte> QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::generate_object_bytes(std::pair<KeyShareIter, KeyShareIter> key_shares)
{
	std::vector<UByte> obj_bytes;
	UShort size = static_cast<UShort>(std::distance(key_shares.first, key_shares.second));
	UShort list_length = 0;

	for (auto& i = key_shares.first; i < key_shares.second; i++)
	{
		auto key_type = TLSKeyShareEntryLittleEndian::generate_object_bytes(static_cast<UShort>(i->second), i->first);
		for (auto j = 0; j < key_type.size(); j++)
		{
			obj_bytes.push_back(key_type[j]);
		}
		list_length += key_type.size();
	}
	obj_bytes.insert(obj_bytes.begin(), list_length >> 8 & 0xFF);
	obj_bytes.insert(obj_bytes.begin() + 1, list_length & 0xFF);
	return obj_bytes;
}

QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::generate_object(std::pair<KeyShareIter, KeyShareIter> key_shares)
{
	auto obj_bytes = generate_object_bytes(key_shares);
	return TLSKeyShareEntryLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::get_tls_key_share_full_length() const
{
	return get_tls_key_share_length() + 2;
}

UShort QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::get_tls_key_share_length() const
{
	return static_cast<UShort>(client_shares_[0] << 8 | client_shares_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::get_tls_key_share() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(client_shares_.cbegin() + 2, client_shares_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSKeyShareClientHelloLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(client_shares_.cbegin(), client_shares_.cend());
}


// TLS Key Share Client Hello View


QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSKeyShareClientHelloView::get_extension_type()
{
	return TLSExtensionType::KEY_SHARE;
}

std::vector<UByte> QVPN::Core::DataStructures::TLSKeyShareClientHelloView::generate_object_bytes(std::pair<KeyShareIter, KeyShareIter> key_shares)
{
	return TLSKeyShareClientHelloLittleEndian::generate_object_bytes(std::move(key_shares));
}

QVPN::Core::DataStructures::TLSKeyShareEntryLittleEndian QVPN::Core::DataStructures::TLSKeyShareClientHelloView::generate_object(std::pair<KeyShareIter, KeyShareIter> key_shares)
{
	return TLSKeyShareClientHelloLittleEndian::generate_object(std::move(key_shares));
}

UShort QVPN::Core::DataStructures::TLSKeyShareClientHelloView::get_tls_key_share_full_length() const
{
	return get_tls_key_share_length() + 2;
}

UShort QVPN::Core::DataStructures::TLSKeyShareClientHelloView::get_tls_key_share_length() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSKeyShareClientHelloView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSKeyShareClientHelloView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSKeyShareClientHelloView::get_tls_key_share() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 2, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSKeyShareClientHelloView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSKeyShareClientHelloView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSKeyShareClientHelloView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS Cipher Suite LE


std::vector<UByte> QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::generate_object_bytes(UShort length)
{
	auto full_length = length + sizeof(length);
	auto obj_bytes = TLSTools::vector_bytes_generator<UByte>(full_length, 2);
	obj_bytes[0] = length >> 8 & 0xFF;
	obj_bytes[1] = length & 0xFF;
	return obj_bytes;
}

QVPN::Core::DataStructures::TLSCipherSuitLittleEndian QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::generate_object(UShort length)
{
	auto obj_bytes = generate_object_bytes(length);
	return TLSCipherSuitLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::get_tls_ciphers_full_length() const
{
	return get_tls_ciphers_length() + 2;
}

UShort QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::get_tls_ciphers_length() const
{
	return static_cast<UShort>(ciphers_[0] << 8 | ciphers_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::get_cipher_suites() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(ciphers_.cbegin() + 2, ciphers_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSCipherSuitLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(ciphers_.cbegin(), ciphers_.cend());
}


// TLS Cipher Suite View


std::vector<UByte> QVPN::Core::DataStructures::TLSCipherSuitView::generate_object_bytes(UShort length)
{
	return TLSCipherSuitLittleEndian::generate_object_bytes(length);
}

QVPN::Core::DataStructures::TLSCipherSuitLittleEndian QVPN::Core::DataStructures::TLSCipherSuitView::generate_object(UShort length)
{
	return TLSCipherSuitLittleEndian::generate_object(length);
}

UShort QVPN::Core::DataStructures::TLSCipherSuitView::get_tls_ciphers_full_length() const
{
	return get_tls_ciphers_length() + 2;
}

UShort QVPN::Core::DataStructures::TLSCipherSuitView::get_tls_ciphers_length() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSCipherSuitView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSCipherSuitView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSCipherSuitView::get_cipher_suites() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 2, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSCipherSuitView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSCipherSuitView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSCipherSuitView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS Compression LE


std::vector<UByte> QVPN::Core::DataStructures::TLSCompressionLittleEndian::generate_object_bytes(UByte length)
{
	auto full_length = length + sizeof(length);
	auto obj_bytes = TLSTools::vector_bytes_generator<UByte>(full_length, 1);
	obj_bytes[0] = length;
	return obj_bytes;
}

QVPN::Core::DataStructures::TLSCompressionLittleEndian QVPN::Core::DataStructures::TLSCompressionLittleEndian::generate_object(UByte length)
{
	auto obj_bytes = generate_object_bytes(length);
	return TLSCompressionLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSCompressionLittleEndian::get_tls_compressions_full_length() const
{
	return get_tls_compressions_length() + 1;
}

UByte QVPN::Core::DataStructures::TLSCompressionLittleEndian::get_tls_compressions_length() const
{
	return compressions_[0];
}

std::pair<QVPN::Core::DataStructures::TLSCompressionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSCompressionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSCompressionLittleEndian::get_tls_compressions() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(compressions_.cbegin() + 1, compressions_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSCompressionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSCompressionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSCompressionLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(compressions_.cbegin(), compressions_.cend());
}


// TLS Compression View


std::vector<UByte> QVPN::Core::DataStructures::TLSCompressionView::generate_object_bytes(UByte length)
{
	return TLSCompressionLittleEndian::generate_object_bytes(length);
}

QVPN::Core::DataStructures::TLSCompressionLittleEndian QVPN::Core::DataStructures::TLSCompressionView::generate_object(UByte length)
{
	return TLSCompressionLittleEndian::generate_object(length);
}

UShort QVPN::Core::DataStructures::TLSCompressionView::get_tls_compressions_full_length() const
{
	return get_tls_compressions_length() + 1;
}

UByte QVPN::Core::DataStructures::TLSCompressionView::get_tls_compressions_length() const
{
	return data_[0];
}

std::pair<QVPN::Core::DataStructures::TLSCompressionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSCompressionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSCompressionView::get_tls_compressions() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 1, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSCompressionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSCompressionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSCompressionView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

UShort QVPN::Core::DataStructures::TLSExtensionsLittleEndian::get_tls_extensions_full_length() const
{
	return get_tls_extensions_length() + 2;
}

UShort QVPN::Core::DataStructures::TLSExtensionsLittleEndian::get_tls_extensions_length() const
{
	return static_cast<UShort>(extensions_[0] << 8 | extensions_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSExtensionsLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSExtensionsLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSExtensionsLittleEndian::get_tls_extensions() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(extensions_.cbegin() + 2, extensions_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSExtensionsLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSExtensionsLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSExtensionsLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(extensions_.cbegin(), extensions_.cend());
}

UShort QVPN::Core::DataStructures::TLSExtensionsView::get_tls_extensions_full_length() const
{
	return get_tls_extensions_length() + 2;
}

UShort QVPN::Core::DataStructures::TLSExtensionsView::get_tls_extensions_length() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSExtensionsView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSExtensionsView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSExtensionsView::get_tls_extensions() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 2, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSExtensionsView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSExtensionsView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSExtensionsView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

// TLS Client helper func

template <std::integral scheme_type, std::random_access_iterator Iter >
void unified_parse_client_scheme(QVPN::Core::DataStructures::TLS13_HelloPacketScheme<scheme_type>& scheme, Iter first, Iter last)
{
	size_t start = 2;
	QVPN::Core::DataStructures::TLSRandomView r(first + start, last);
	size_t end = start + r.get_tls_random_full_length();
	scheme.random = std::make_pair<>(start, end);

	QVPN::Core::DataStructures::TLSSessionIDView s(first + end, last);
	start = end;
	end = start + s.get_tls_id_full_length();
	scheme.session = std::make_pair<>(start, end);

	QVPN::Core::DataStructures::TLSCipherSuitView c(first + end, last);
	start = end;
	end = start + c.get_tls_ciphers_full_length();
	scheme.ciphers = std::make_pair<>(start, end);

	QVPN::Core::DataStructures::TLSCompressionView comp(first + end, last);
	start = end;
	end = start + comp.get_tls_compressions_full_length();
	scheme.compressions = std::make_pair<>(start, end);

	QVPN::Core::DataStructures::TLSExtensionsView ext(first + end, last);
	start = end;
	end = start + ext.get_tls_extensions_full_length();
	scheme.extensions = std::make_pair<>(start, end);
}

// TLS Client Hello LE


void QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::parse_scheme()
{
	unified_parse_client_scheme<size_t, UByte*>(scheme_, data_.data(), data_.data() + data_.size());
}

bool QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::is_valid() const
{
	auto ver = static_cast<TLSProtocolVersion>(get_tls_version());
	if (ver != TLSProtocolVersion::TLS12)
		return false;
	return true;
}

QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::OverlayProtocolType QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::get_overlay_protocol_type()
{
	return OverlayProtocolType::CLIENT_HELLO;
}

UShort QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::get_tls_version() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

QVPN::Core::DataStructures::TLSRandomView QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::get_tls_random() const
{
	TLSRandomView random(const_cast<UByte*>(data_.data()) + scheme_.random.first, const_cast<UByte*>(data_.data()) + scheme_.random.second);
	return random;
}

QVPN::Core::DataStructures::TLSSessionIDView QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::get_tls_session() const
{
	TLSSessionIDView session(const_cast<UByte*>(data_.data()) + scheme_.session.first, const_cast<UByte*>(data_.data()) + scheme_.session.second);
	return session;
}

QVPN::Core::DataStructures::TLSCipherSuitView QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::get_tls_cipher_suites() const
{
	TLSCipherSuitView ciphers_view(const_cast<UByte*>(data_.data()) + scheme_.ciphers.first, const_cast<UByte*>(data_.data()) + scheme_.ciphers.second);
	return ciphers_view;
}

QVPN::Core::DataStructures::TLSCompressionView QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::get_tls_compression_methods() const
{
	TLSCompressionView compr_view(const_cast<UByte*>(data_.data()) + scheme_.compressions.first, const_cast<UByte*>(data_.data()) + scheme_.compressions.second);
	return compr_view;
}

QVPN::Core::DataStructures::TLSExtensionsView QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::get_tls_extensions_data() const
{
	TLSExtensionsView exts_view(const_cast<UByte*>(data_.data()) + scheme_.extensions.first, const_cast<UByte*>(data_.data()) + scheme_.extensions.second);
	return exts_view;
}

QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::get_tls_sni_data() const
{
	auto exts = get_tls_extensions_data();
	auto [b, e] = exts.get_tls_extensions();
	for (auto i = b; i < e;)
	{
		TLSExtensionView ext(const_cast<UByte*>(i), const_cast<UByte*>(e));
		if (ext.get_tls_ext_type() == TLSExtensionType::SERVER_NAME)
			return TLSServerNameIndicationExtensionView(const_cast<UByte*>(i), const_cast<UByte*>(e));
		i += ext.get_tls_ext_full_length();
	}
	return TLSServerNameIndicationExtensionView(const_cast<UByte*>(b), const_cast<UByte*>(b));
}

std::pair<QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_ClientHelloPacketLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin(), data_.cend());
}



// TLS Client Hello View


void QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::parse_scheme()
{
	unified_parse_client_scheme<size_t, UByte*>(scheme_, data_, data_ + size_);
}

QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::OverlayProtocolType QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::get_overlay_protocol_type()
{
	return OverlayProtocolType::CLIENT_HELLO;
}

UShort QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::get_tls_version() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

QVPN::Core::DataStructures::TLSRandomView QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::get_tls_random() const
{
	TLSRandomView random(data_ + scheme_.random.first, data_ + scheme_.random.second);
	return random;
}

QVPN::Core::DataStructures::TLSSessionIDView QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::get_tls_session() const
{
	TLSSessionIDView session(data_ + scheme_.session.first, data_ + scheme_.session.second);
	return session;
}

QVPN::Core::DataStructures::TLSCipherSuitView QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::get_tls_cipher_suites() const
{
	TLSCipherSuitView ciphers_view(data_ + scheme_.ciphers.first, data_ + scheme_.ciphers.second);
	return ciphers_view;
}

QVPN::Core::DataStructures::TLSCompressionView QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::get_tls_compression_methods() const
{
	TLSCompressionView compr_view(data_ + scheme_.compressions.first, data_ + scheme_.compressions.second);
	return compr_view;
}

QVPN::Core::DataStructures::TLSExtensionsView QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::get_tls_extensions_data() const
{
	TLSExtensionsView exts_view(data_ + scheme_.extensions.first, data_ + scheme_.extensions.second);
	return exts_view;
}

QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::get_tls_sni_data() const
{
	auto exts = get_tls_extensions_data();
	auto [b, e] = exts.get_tls_extensions();
	for (auto i = b; i < e;)
	{
		TLSExtensionView ext(const_cast<UByte*>(i), const_cast<UByte*>(e));
		if (ext.get_tls_ext_type() == TLSExtensionType::SERVER_NAME)
			return TLSServerNameIndicationExtensionView(const_cast<UByte*>(i), const_cast<UByte*>(e));
		i += ext.get_tls_ext_full_length();
	}
	return TLSServerNameIndicationExtensionView(const_cast<UByte*>(b), const_cast<UByte*>(b));
}

std::pair<QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_ClientHelloPacketView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

// TLS SNI EXT LE

QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::get_extension_type()
{
	return TLSExtensionType::SERVER_NAME;
}

std::vector<UByte> QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::generate_object_bytes(std::pair<SNIIter, SNIIter> hosts)
{
	std::vector<UByte> res;
	UShort size = static_cast<UShort>(std::distance(hosts.first, hosts.second));
	UShort list_length = 0;

	for (auto i = 0; i < size; i++)
	{
		auto elem = hosts.first + i;
		auto obj_bytes = TLSServerNameIndicationEntryLittleEndian::generate_object_bytes(elem->size(), *elem);
		list_length += obj_bytes.size();
		std::copy(obj_bytes.begin(), obj_bytes.end(), std::back_inserter(res));
	}
	res.insert(res.begin(), static_cast<UByte>(list_length >> 8 & 0xFF));
	res.insert(res.begin() + 1, static_cast<UByte>(list_length & 0xFF));
	return res;
}

QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::generate_object(std::pair<SNIIter, SNIIter> hosts)
{
	auto obj_bytes = generate_object_bytes(hosts);
	return TLSServerNameIndicationExtensionLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::get_tls_sni_full_length() const
{
	return get_tls_sni_length() + 2;
}

UShort QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::get_tls_sni_length() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::get_tls_sni_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin() + 2, data_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin(), data_.cend());
}


// TLS SNI EXT VIEW


QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::get_extension_type()
{
	return TLSExtensionType::SERVER_NAME;
}

std::vector<UByte> QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::generate_object_bytes(std::pair<SNIIter, SNIIter> hosts)
{
	return TLSServerNameIndicationExtensionLittleEndian::generate_object_bytes(std::move(hosts));
}

QVPN::Core::DataStructures::TLSServerNameIndicationExtensionLittleEndian QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::generate_object(std::pair<SNIIter, SNIIter> hosts)
{
	return TLSServerNameIndicationExtensionLittleEndian::generate_object(std::move(hosts));
}

UShort QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::get_tls_sni_full_length() const
{
	return get_tls_sni_length() + 2;
}

UShort QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::get_tls_sni_length() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::get_tls_sni_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 2, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSServerNameIndicationExtensionView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

/////////


template <std::integral scheme_type, std::random_access_iterator Iter> 
void unified_server_parse_scheme(QVPN::Core::DataStructures::TLS13_HelloPacketScheme<scheme_type>& scheme, Iter first, Iter last)
{
	size_t start = 2;
	QVPN::Core::DataStructures::TLSRandomView r(first, last);
	size_t end = start + r.get_tls_random_full_length();
	scheme.random = std::make_pair<>(start, end);

	QVPN::Core::DataStructures::TLSSessionIDView s(first + end, last);
	start = end;
	end = start + s.get_tls_id_full_length();
	scheme.session = std::make_pair<>(start, end);

	start = end;
	end = start + sizeof(QVPN::Core::DataStructures::TLSCipherSuite);
	scheme.ciphers = std::make_pair<>(start, end);

	start = end;
	end = start + sizeof(QVPN::Core::DataStructures::TLSCompressionMethod);
	scheme.compressions = std::make_pair<>(start, end);

	QVPN::Core::DataStructures::TLSExtensionsView ext(first + end, last);
	start = end;
	end = start + ext.get_tls_extensions_full_length();
	scheme.extensions = std::make_pair<>(start, end);
}


////

// TLS Server Hello LE


void QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::parse_scheme()
{
	unified_server_parse_scheme(scheme_, data_.data(), data_.data() + data_.size());
}

QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::TLS13_ServerHelloPacketLittleEndian(UByte* begin, UByte* end)
{
	std::copy(begin, end, std::back_inserter(data_));
	parse_scheme();
}

QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::OverlayProtocolType QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::get_overlay_protocol_type()
{
	return OverlayProtocolType::SERVER_HELLO;
}

UShort QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::get_tls_version() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

QVPN::Core::DataStructures::TLSRandomView QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::get_tls_random() const
{
	return TLSRandomView(const_cast<UByte*>(data_.data()) + scheme_.random.first, const_cast<UByte*>(data_.data()) + scheme_.random.second);
}

QVPN::Core::DataStructures::TLSSessionIDView QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::get_tls_session() const
{
	return TLSSessionIDView(const_cast<UByte*>(data_.data() + scheme_.session.first), const_cast<UByte*>(data_.data()) + scheme_.session.second);
}

QVPN::Core::DataStructures::TLSCipherSuite QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::get_tls_cipher_suite() const
{
	return static_cast<TLSCipherSuite>(data_[scheme_.ciphers.first] << 8 | data_[scheme_.ciphers.second]);
}

QVPN::Core::DataStructures::TLSCompressionMethod QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::get_tls_compression_method() const
{
	return static_cast<TLSCompressionMethod>(data_[scheme_.compressions.first]);
}

QVPN::Core::DataStructures::TLSExtensionsView QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::get_tls_extensions_data() const
{
	return TLSExtensionsView(const_cast<UByte*>(data_.data()) + scheme_.extensions.first, const_cast<UByte*>(data_.data()) + scheme_.extensions.second);
}

std::pair<QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_ServerHelloPacketLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin(), data_.cend());
}


// TLS Server Hello View


void QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::parse_scheme()
{
	unified_server_parse_scheme(scheme_, data_, data_ + size_);
}

QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::TLS13_ServerHelloPacketView(UByte* begin, UByte* end)
{
	data_ = begin;
	size_ = std::distance(begin, end);
	parse_scheme();
}

QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::OverlayProtocolType QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::get_overlay_protocol_type()
{
	return OverlayProtocolType::SERVER_HELLO;
}

UShort QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::get_tls_version() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

QVPN::Core::DataStructures::TLSRandomView QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::get_tls_random() const
{
	return TLSRandomView(data_ + scheme_.random.first, data_ + scheme_.random.second);
}

QVPN::Core::DataStructures::TLSSessionIDView QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::get_tls_session() const
{
	return TLSSessionIDView(data_ + scheme_.session.first, data_ + scheme_.session.second);
}

QVPN::Core::DataStructures::TLSCipherSuite QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::get_tls_cipher_suite() const
{
	return static_cast<TLSCipherSuite>(data_[scheme_.ciphers.first] << 8 | data_[scheme_.ciphers.second]);
}

QVPN::Core::DataStructures::TLSCompressionMethod QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::get_tls_compression_method() const
{
	return static_cast<TLSCompressionMethod>(data_[scheme_.compressions.first]);
}

QVPN::Core::DataStructures::TLSExtensionsView QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::get_tls_extensions_data() const
{
	return TLSExtensionsView(data_ + scheme_.extensions.first, data_ + scheme_.extensions.second);
}

std::pair<QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_ServerHelloPacketView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS Message LE


QVPN::Core::DataStructures::TLS13_MessageLittleEndian::TLS13_MessageLittleEndian(UByte* begin, UByte* end)
{
	auto length = static_cast<UInt>(0 << 24 | data_[1] << 16 | data_[2] << 8 | data_[3]) + 4;
	std::copy(begin, begin + length, std::back_inserter(data_));
}

QVPN::Core::DataStructures::TLSMessageType QVPN::Core::DataStructures::TLS13_MessageLittleEndian::get_tls_msg_type() const
{
	return static_cast<TLSMessageType>(data_[0]);
}

UInt QVPN::Core::DataStructures::TLS13_MessageLittleEndian::get_tls_msg_length() const
{
	return static_cast<UInt>(0 << 24 | data_[1] << 16 | data_[2] << 8 | data_[3]);
}

UInt QVPN::Core::DataStructures::TLS13_MessageLittleEndian::get_tls_msg_full_length() const
{
	return get_tls_msg_length() + 4;
}

QVPN::Core::DataStructures::TLS13_MessageLittleEndian::OverlayProtocolType QVPN::Core::DataStructures::TLS13_MessageLittleEndian::get_overlay_protocol_type()
{
	return OverlayProtocolType::HANDSHAKE;
}

std::pair<QVPN::Core::DataStructures::TLS13_MessageLittleEndian::DataIterator_t, QVPN::Core::DataStructures::TLS13_MessageLittleEndian::DataIterator_t> QVPN::Core::DataStructures::TLS13_MessageLittleEndian::get_tls_msg_data()
{
	return std::pair<DataIterator_t, DataIterator_t>(data_.begin() + 4, data_.end());
}

std::pair<QVPN::Core::DataStructures::TLS13_MessageLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_MessageLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_MessageLittleEndian::get_tls_msg_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin() + 4, data_.cend());
}

std::pair<QVPN::Core::DataStructures::TLS13_MessageLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_MessageLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_MessageLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin(), data_.cend());
}


// TLS Message View

QVPN::Core::DataStructures::TLS13_MessageView::TLS13_MessageView(UByte* begin, UByte* end)
{
	data_ = begin;
	size_ = get_tls_msg_full_length();
}

QVPN::Core::DataStructures::TLSMessageType QVPN::Core::DataStructures::TLS13_MessageView::get_tls_msg_type() const
{
	return static_cast<TLSMessageType>(data_[0]);
}

UInt QVPN::Core::DataStructures::TLS13_MessageView::get_tls_msg_length() const
{
	return static_cast<UInt>(0 << 24 | data_[1] << 16 | data_[2] << 8 | data_[3]);
}

UInt QVPN::Core::DataStructures::TLS13_MessageView::get_tls_msg_full_length() const
{
	return get_tls_msg_length() + 4;
}

QVPN::Core::DataStructures::TLS13_MessageView::OverlayProtocolType QVPN::Core::DataStructures::TLS13_MessageView::get_overlay_protocol_type()
{
	return OverlayProtocolType::HANDSHAKE;
}

std::pair<QVPN::Core::DataStructures::TLS13_MessageView::DataIterator_t, QVPN::Core::DataStructures::TLS13_MessageView::DataIterator_t> QVPN::Core::DataStructures::TLS13_MessageView::get_tls_msg_data()
{
	return std::pair<DataIterator_t, DataIterator_t>(data_ + 4, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLS13_MessageView::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_MessageView::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_MessageView::get_tls_msg_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 4, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLS13_MessageView::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_MessageView::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_MessageView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

// TLS SNI Entry LE

std::vector<UByte> QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::generate_object_bytes(UShort length, std::string_view host)
{
	std::vector<UByte> obj_bytes;
	size_t size = length + sizeof(length) + sizeof(TLSSNIRecordType);
	auto n = std::max(size, host.size());
	//auto obj_bytes = TLSTools::vector_bytes_generator<UShort>(size, 3 + host.size());
	obj_bytes.push_back(static_cast<UByte>(TLSSNIRecordType::HOST_NAME));
	obj_bytes.push_back(static_cast<UByte>(length >> 8 & 0xFF));
	obj_bytes.push_back(static_cast<UByte>(length & 0xFF));
	obj_bytes.insert(obj_bytes.begin() + 3, host.begin(), host.end());
	return obj_bytes;
}

QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::generate_object(UShort length, std::string_view host)
{
	auto obj_bytes = generate_object_bytes(length);
	return TLSServerNameIndicationEntryLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::get_tls_sni_full_length() const
{
	return get_tls_sni_length() + 3;
}

UShort QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::get_tls_sni_length() const
{
	return static_cast<UShort>(data_[1] << 8 | data_[2]);
}

QVPN::Core::DataStructures::TLSSNIRecordType QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::get_tls_sni_record_type() const
{
	return static_cast<TLSSNIRecordType>(data_[0]);
}

std::pair<QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::get_tls_sni_entry_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin() + 3, data_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin(), data_.cend());
}


// TLS SNI Entry View


std::vector<UByte> QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::generate_object_bytes(UShort length, std::string_view host)
{
	return TLSServerNameIndicationEntryLittleEndian::generate_object_bytes(length, host);
}

QVPN::Core::DataStructures::TLSServerNameIndicationEntryLittleEndian QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::generate_object(UShort length, std::string_view host)
{
	return TLSServerNameIndicationEntryLittleEndian::generate_object(length, host);
}

UShort QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::get_tls_sni_full_length() const
{
	return get_tls_sni_length() + 3;
}

UShort QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::get_tls_sni_length() const
{
	return static_cast<UShort>(data_[1] << 8 | data_[2]);
}

QVPN::Core::DataStructures::TLSSNIRecordType QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::get_tls_sni_record_type() const
{
	return static_cast<TLSSNIRecordType>(data_[0]);
}

std::pair<QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::get_tls_sni_entry_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + 3, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSServerNameIndicationEntryView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS SupVer Entry LE


std::vector<UByte> QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::generate_object_bytes(UShort length, TLSProtocolVersion version)
{
	std::vector<UByte> obj_bytes;
	obj_bytes.push_back(static_cast<UByte>(version >> 8 & 0xFF));
	obj_bytes.push_back(static_cast<UByte>(version & 0xFF));
	return obj_bytes;
}

QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::generate_object(UShort length, TLSProtocolVersion version)
{
	auto obj_bytes = generate_object_bytes(length, version);
	return TLSSupportedVersionsEntryLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::get_tls_versions_full_length() const
{
	return 2;
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::get_tls_versions_length() const
{
	return 2;
}

QVPN::Core::DataStructures::TLSProtocolVersion QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::get_tls_supported_version_value() const
{
	return static_cast<TLSProtocolVersion>(data_[0] << 8 | data_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::get_tls_supported_version() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.begin(), data_.end());
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.begin(), data_.end());
}


// TLS SupVer Entry View

std::vector<UByte> QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::generate_object_bytes(UShort length, TLSProtocolVersion version)
{
	return TLSSupportedVersionsEntryLittleEndian::generate_object_bytes(length, version);
}

QVPN::Core::DataStructures::TLSSupportedVersionsEntryLittleEndian QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::generate_object(UShort length, TLSProtocolVersion version)
{
	return TLSSupportedVersionsEntryLittleEndian::generate_object(length, version);
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::get_tls_versions_full_length() const
{
	return 2;
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::get_tls_versions_length() const
{
	return 2;
}

QVPN::Core::DataStructures::TLSProtocolVersion QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::get_tls_supported_version_value() const
{
	return static_cast<TLSProtocolVersion>(data_[0] << 8 | data_[1]);
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::get_tls_supported_version() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsEntryView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS1.3 Default Generation Strategy

QVPN::Core::DataStructures::TLSProtocolVersion QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_legacy_version() const
{
	return TLSProtocolVersion::TLS12;
}

UByte QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_session_length() const
{
	return 32;
}

UShort QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_cipher_length() const
{
	return 34;
}

UShort QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_compression_length() const
{
	return 1;
}

UShort QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_supported_versions_length() const
{
	return 8;
}

std::vector<QVPN::Core::DataStructures::TLSProtocolVersion> QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_supported_versions() const
{
	return std::vector<TLSProtocolVersion>{ TLSProtocolVersion::TLS13, TLSProtocolVersion::TLS12, TLSProtocolVersion::TLS11, TLSProtocolVersion::TLS10 };
}

UShort QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_key_share_length() const
{
	return 32;
}

std::vector<std::pair<QVPN::Core::DataStructures::TLSKeyTypes, QVPN::Core::DataStructures::TLSKeyTypesLength>> QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_key_share() const
{
	return std::vector<std::pair<TLSKeyTypes, TLSKeyTypesLength>>{ {TLSKeyTypes::X25519, TLSKeyTypesLength::X25519_LENGTH} };
}

UShort QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_sni_length() const
{
	return 6;
}

std::vector<std::string_view> QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_sni_hosts() const
{
	return std::vector<std::string_view>{ "vk.com" };
}

std::vector<std::string_view> QVPN::Core::DataStructures::TLS13_DefaultClientHelloGenerationStrategy::get_sni_hosts(std::string_view host) const
{
	return std::vector<std::string_view>{ host };
}

// TLS Default Client hello Gen strategy


QVPN::Core::DataStructures::TLSProtocolVersion QVPN::Core::DataStructures::TLS13_DefaultServerHelloGenerationStrategy::get_legacy_version() const
{
	return TLSProtocolVersion::TLS12;
}

UByte QVPN::Core::DataStructures::TLS13_DefaultServerHelloGenerationStrategy::get_session_length() const
{
	return 32;
}

QVPN::Core::DataStructures::TLSCipherSuite QVPN::Core::DataStructures::TLS13_DefaultServerHelloGenerationStrategy::get_cipher_suite() const
{
	return TLSCipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
}

QVPN::Core::DataStructures::TLSCompressionMethod QVPN::Core::DataStructures::TLS13_DefaultServerHelloGenerationStrategy::get_compression_method() const
{
	return TLSCompressionMethod::NULL_COMPRESSION;
}

UShort QVPN::Core::DataStructures::TLS13_DefaultServerHelloGenerationStrategy::get_supported_versions_length() const
{
	return 2;
}

QVPN::Core::DataStructures::TLSProtocolVersion QVPN::Core::DataStructures::TLS13_DefaultServerHelloGenerationStrategy::get_supported_version() const
{
	return QVPN::Core::DataStructures::TLSProtocolVersion::TLS13;
}


// TLS Record LE


QVPN::Core::DataStructures::TLSRecordType QVPN::Core::DataStructures::TLS13_RecordLittleEndian::get_tls_record_type() const
{
	return static_cast<TLSRecordType>(data_[0]);
}

QVPN::Core::DataStructures::TLSProtocolVersion QVPN::Core::DataStructures::TLS13_RecordLittleEndian::get_tls_protocol_version() const
{
	return static_cast<TLSProtocolVersion>(data_[1] << 8 | data_[2]);
}

UShort QVPN::Core::DataStructures::TLS13_RecordLittleEndian::get_tls_record_full_length() const
{
	return get_tls_record_length() + sizeof(TLSRecordType) + sizeof(TLSProtocolVersion) + sizeof(UShort);
}

UShort QVPN::Core::DataStructures::TLS13_RecordLittleEndian::get_tls_record_length() const
{
	return static_cast<UShort>(data_[3] << 8 | data_[4]);
}

std::pair<QVPN::Core::DataStructures::TLS13_RecordLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_RecordLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_RecordLittleEndian::get_tls_record_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.begin() + sizeof(TLSRecordType) + sizeof(TLSProtocolVersion) + sizeof(UShort), data_.end());
}

std::pair<QVPN::Core::DataStructures::TLS13_RecordLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_RecordLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_RecordLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.begin(), data_.end());
}


// TLS Record View


QVPN::Core::DataStructures::TLSRecordType QVPN::Core::DataStructures::TLS13_RecordView::get_tls_record_type() const
{
	return static_cast<TLSRecordType>(data_[0]);
}

QVPN::Core::DataStructures::TLSProtocolVersion QVPN::Core::DataStructures::TLS13_RecordView::get_tls_protocol_version() const
{
	return static_cast<TLSProtocolVersion>(data_[1] << 8 | data_[2]);
}

UShort QVPN::Core::DataStructures::TLS13_RecordView::get_tls_record_full_length() const
{
	return get_tls_record_length() + sizeof(TLSRecordType) + sizeof(TLSProtocolVersion) + sizeof(UShort);
}

UShort QVPN::Core::DataStructures::TLS13_RecordView::get_tls_record_length() const
{
	return static_cast<UShort>(data_[3] << 8 | data_[4]);
}

std::pair<QVPN::Core::DataStructures::TLS13_RecordView::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_RecordView::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_RecordView::get_tls_record_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_ + sizeof(TLSRecordType) + sizeof(TLSProtocolVersion) + sizeof(UShort), data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLS13_RecordView::DataIterator_t, QVPN::Core::DataStructures::TLS13_RecordView::DataIterator_t> QVPN::Core::DataStructures::TLS13_RecordView::get_tls_record_data()
{
	return std::pair<DataIterator_t, DataIterator_t>(data_ + sizeof(TLSRecordType) + sizeof(TLSProtocolVersion) + sizeof(UShort), data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLS13_RecordView::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_RecordView::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_RecordView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}


// TLS 1.3 Application Data LE


QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian::OverlayProtocolType QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian::get_overlay_protocol_type()
{
	return OverlayProtocolType::APPLICATION_DATA;
}

std::pair<QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian::get_app_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin(), data_.cend());
}

std::pair<QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_ApplicationDataLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.cbegin(), data_.cend());
}


// TLS 1.3 Application Data View


QVPN::Core::DataStructures::TLS13_ApplicationDataView::OverlayProtocolType QVPN::Core::DataStructures::TLS13_ApplicationDataView::get_overlay_protocol_type()
{
	return OverlayProtocolType::APPLICATION_DATA;
}

std::pair<QVPN::Core::DataStructures::TLS13_ApplicationDataView::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_ApplicationDataView::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_ApplicationDataView::get_app_data() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLS13_ApplicationDataView::ConstDataIterator_t, QVPN::Core::DataStructures::TLS13_ApplicationDataView::ConstDataIterator_t> QVPN::Core::DataStructures::TLS13_ApplicationDataView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

// TLS 1.3 Default Record Gen Strategy

QVPN::Core::DataStructures::TLSProtocolVersion QVPN::Core::DataStructures::TLS13_DefaultRecordGenerationStrategy::get_legacy_version() const
{
	return TLSProtocolVersion::TLS12;
}

// QTunnel tcp view scheme

QVPN::Core::DataStructures::QTunnelTCPViewScheme::QTunnelTCPViewScheme(UByte* begin, UByte* end)
{
	length_ = std::distance(begin, end);
	data_ = begin;
}

UInt QVPN::Core::DataStructures::QTunnelTCPViewScheme::get_seq() const
{
	return static_cast<UInt>(data_[0] << 24 | data_[1] << 16 | data_[2] << 8 | data_[3]);
}

UInt QVPN::Core::DataStructures::QTunnelTCPViewScheme::get_ack() const
{
	return static_cast<UInt>(data_[4] << 24 | data_[5] << 16 | data_[6] << 8 | data_[7]);
}

UByte QVPN::Core::DataStructures::QTunnelTCPViewScheme::get_flags() const
{
	return static_cast<UByte>(data_[8]);
}

UByte QVPN::Core::DataStructures::QTunnelTCPViewScheme::get_offset() const
{
	return static_cast<UByte>(data_[9]);
}

UShort QVPN::Core::DataStructures::QTunnelTCPViewScheme::get_window() const
{
	return static_cast<UShort>(data_[10] << 8 & 0xFF | data_[11]);
}

UShort QVPN::Core::DataStructures::QTunnelTCPViewScheme::get_urgent_pointer() const
{
	return static_cast<UShort>(data_[12] << 8 | data_[13]);
}

std::pair<UByte*, UByte*> QVPN::Core::DataStructures::QTunnelTCPViewScheme::get_options() const
{
	return std::pair<UByte*, UByte*>(data_ + 14, data_ + length_);
}

std::vector<UByte> QVPN::Core::DataStructures::QTunnelTCPViewScheme::generate_bytes(TcpPacketView tcp_packet)
{
	std::vector<UByte> res{};
	auto seq = tcp_packet.get_tcp_seq_number();
	auto ack = tcp_packet.get_tcp_ack_number();
	auto flags = tcp_packet.get_tcp_flags();

	auto offset = tcp_packet.get_tcp_header_length();
	auto window = tcp_packet.get_tcp_window_size();
	auto urgent = tcp_packet.get_tcp_urgent_pointer();

	auto [b, e] = tcp_packet.get_tcp_options();

	res.push_back(seq >> 24 & 0xFF); res.push_back(seq >> 16 & 0xFF);  res.push_back(seq >> 8 & 0xFF); res.push_back(seq & 0xFF);
	res.push_back(ack >> 24 & 0xFF); res.push_back(ack >> 16 & 0xFF);  res.push_back(ack >> 8 & 0xFF); res.push_back(ack & 0xFF);

	res.push_back(flags);
	res.push_back(offset);

	res.push_back(window >> 8 & 0xFF); res.push_back(window & 0xFF);
	res.push_back(urgent >> 8 & 0xFF); res.push_back(urgent & 0xFF);

	std::copy(b, e, std::back_inserter(res));

	return res;
}

QVPN::Core::DataStructures::QTunnelUDPViewScheme::QTunnelUDPViewScheme(UByte* begin, UByte* end)
{
	length_ = std::distance(begin, end);
	data_ = begin;
}

UShort QVPN::Core::DataStructures::QTunnelUDPViewScheme::get_length() const
{
	return static_cast<UShort>(data_[0] << 8 | data_[1]);
}

std::vector<UByte> QVPN::Core::DataStructures::QTunnelUDPViewScheme::generate_bytes(UdpPacketView udp_packet)
{
	std::vector<UByte> bytes{};
	auto length = udp_packet.get_udp_length();
	bytes.push_back(length >> 8 & 0xFF);
	bytes.push_back(length & 0xFF);
	return bytes;
}


// TLS Server Sup ver ext le


QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::get_extension_type()
{
	return TLSExtensionType::SUPPORTED_VERSIONS;
}

std::vector<UByte> QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::generate_object_bytes(TLSProtocolVersion version)
{
	std::vector<UByte> obj_bytes;

	auto ver = TLSSupportedVersionsEntryLittleEndian::generate_object_bytes(2, version);

	obj_bytes.push_back(ver[0]);
	obj_bytes.push_back(ver[1]);

	return obj_bytes;
}

QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::generate_object(TLSProtocolVersion version)
{
	auto obj_bytes = generate_object_bytes(version);
	return TLSSupportedVersionsServerHelloExtensionLittleEndian(obj_bytes.begin(), obj_bytes.end());
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::get_tls_versions_full_length() const
{
	return get_tls_versions_length();
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::get_tls_versions_length() const
{
	return static_cast<UShort>(2);
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::get_tls_supported_version() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(versions_.cbegin(), versions_.cend());
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(versions_.cbegin(), versions_.cend());
}


// TLS Server SupVer Ext View


QVPN::Core::DataStructures::TLSExtensionType QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::get_extension_type()
{
	return TLSExtensionType::SUPPORTED_VERSIONS;
}

std::vector<UByte> QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::generate_object_bytes(TLSProtocolVersion version)
{
	return TLSSupportedVersionsServerHelloExtensionLittleEndian::generate_object_bytes(version);
}

QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionLittleEndian QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::generate_object(TLSProtocolVersion version)
{
	return TLSSupportedVersionsServerHelloExtensionLittleEndian::generate_object(version);
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::get_tls_versions_full_length() const
{
	return get_tls_versions_length();
}

UShort QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::get_tls_versions_length() const
{
	return static_cast<UByte>(2);
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::get_tls_supported_versions() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

std::pair<QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::ConstDataIterator_t, QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::ConstDataIterator_t> QVPN::Core::DataStructures::TLSSupportedVersionsServerHelloExtensionView::to_bytes() const
{
	return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_, data_ + size_);
}

