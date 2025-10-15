#include "structures.hpp"
#include <sstream>

using Byte = QVPN::Core::DataStructures::Byte;
using UByte = QVPN::Core::DataStructures::UByte;
using UShort = QVPN::Core::DataStructures::UShort;
using UInt = QVPN::Core::DataStructures::UInt;
using ubyte_const_iter = QVPN::Core::DataStructures::ubyte_const_iter;



QVPN::Core::DataStructures::Ipv4PacketLittleEndian::Ipv4PacketLittleEndian(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::parse_packet(UByte* begin, UByte* end)
{
	constexpr auto default_ip_quintet_size = 5;
	constexpr auto bytes_in_quintet = 4;
	constexpr auto default_ip_bytes = default_ip_quintet_size * bytes_in_quintet;
	memcpy(header_, begin, default_ip_bytes);
	auto start = begin + default_ip_bytes;
	//auto _end = (get_ip_header_length() - default_ip_quintet_size) * bytes_in_quintet;
	auto _end = start + (get_ip_header_length() - default_ip_quintet_size);
	for (auto i = start; i < _end; start += sizeof(UByte))
	{
		additional_header_.push_back(*start);
	}
	next_protocol_ = _end;
}

UByte* QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_next_protocol_byte()
{
	return next_protocol_;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_version() const
{
	return header_[0] >> 4;
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

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_protocol() const
{
	return header_[9];
}

UShort QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_checksum() const
{
	UShort first = header_[10] << 8;
	UShort checksum = first | header_[11];
	return checksum;
}

UInt QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_source() const
{
	UInt first = header_[12] << 24;
	UInt second = header_[13] << 16;
	UInt third = header_[14] << 8;
	return first | second | third | header_[15];
}

UInt QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_dest() const
{
	UInt first = header_[16] << 24;
	UInt second = header_[17] << 16;
	UInt third = header_[18] << 8;
	return first | second | third | header_[19];
}

std::pair<ubyte_const_iter, ubyte_const_iter> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ip_additional_header() const
{
	return std::make_pair<>(additional_header_.cbegin(), additional_header_.cend());
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

std::pair<const UByte*, const UByte*> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_src() const
{
	return std::make_pair<>(&header_[12], &header_[15]);
}

std::pair<const UByte*, const UByte*> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_dst() const
{
	return std::make_pair<>(&header_[16], &header_[19]);
}

QVPN::Core::DataStructures::TcpPacketLittleEndian::TcpPacketLittleEndian(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::parse_packet(UByte* begin, UByte* end)
{
	constexpr int default_tcp_quart_size = 5;
	constexpr int bytes_in_quartet = 4;
	constexpr int default_tcp_size = default_tcp_quart_size * bytes_in_quartet;
	auto default_end = begin + default_tcp_size;
	memcpy(header_, begin, default_tcp_size);

	auto start = default_end;
	auto _end = start + (get_tcp_header_length() * bytes_in_quartet);
	for (auto i = start; i < _end; i += 1)
	{
		options_.push_back(*start);
	}
	next_protocol_ = _end; 
}

UByte* QVPN::Core::DataStructures::TcpPacketLittleEndian::get_next_protocol_byte()
{
	return next_protocol_;
}


UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_src_port()
{
	return header_[0] << 8 | header_[1];
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_dst_port()
{
	return header_[2] << 8 | header_[3];
}

UInt QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_seq_number()
{
	return header_[4] << 24 | header_[5] << 16 | header_[6] << 8 | header_[7];
}

UInt QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_ack_number()
{
	return header_[8] << 24 | header_[9] << 16 | header_[10] << 8 | header_[11];
}

UByte QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_header_length()
{
	return header_[12] >> 4;
}

UByte QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_reserved()
{
	return header_[12] & 0xF;
}

UByte QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_flags()
{
	return header_[13];
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_window_size()
{
	return header_[14] << 8 | header_[15];
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_checksum()
{
	return header_[16] << 8 | header_[17];
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_urgent_pointer()
{
	return header_[18] << 8 | header_[19];
}

std::pair<ubyte_const_iter, ubyte_const_iter> QVPN::Core::DataStructures::TcpPacketLittleEndian::get_tcp_options()
{
	return std::pair<decltype(options_)::const_iterator, decltype(options_)::const_iterator>(options_.begin(), options_.end());
}

bool QVPN::Core::DataStructures::TcpPacketLittleEndian::protocol_criteria(UByte protocol)
{
	return (protocol == QVPN::Core::DataStructures::Protocols::TCP) ? true : false;
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_src_port()
{
	return get_tcp_src_port();
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_dst_port()
{
	return get_tcp_dst_port();
}

QVPN::Core::DataStructures::UdpPacketLittleEndian::UdpPacketLittleEndian(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::UdpPacketLittleEndian::parse_packet(UByte* begin, UByte* end)
{
	constexpr int default_udp_size = 8;
	memcpy(header_, begin, default_udp_size);
	next_protocol_ = begin + default_udp_size;
}

UByte* QVPN::Core::DataStructures::UdpPacketLittleEndian::get_next_protocol_byte()
{
	return next_protocol_;
}


UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_udp_src_port()
{
	return header_[0] << 8 | header_[1];
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_udp_dst_port()
{
	return header_[2] << 8 | header_[3];
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_udp_length()
{
	return header_[4] << 8 | header_[5];
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_udp_checksum()
{
	return header_[6] << 8 | header_[7];
}

bool QVPN::Core::DataStructures::UdpPacketLittleEndian::protocol_criteria(UByte protocol)
{
	return (protocol == QVPN::Core::DataStructures::Protocols::UDP) ? true : false;
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_src_port()
{
	return get_udp_src_port();
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_dst_port()
{
	return get_udp_dst_port();
}

QVPN::Core::DataStructures::CustomPacketLittleEndian::CustomPacketLittleEndian(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::CustomPacketLittleEndian::parse_packet(UByte* begin, UByte* end)
{
	std::copy(begin, end, data_.begin());
	next_protocol_ = end;
}

UByte* QVPN::Core::DataStructures::CustomPacketLittleEndian::get_next_protocol_byte()
{
	return next_protocol_;
}

std::pair<ubyte_const_iter, ubyte_const_iter> QVPN::Core::DataStructures::CustomPacketLittleEndian::get_custom_data()
{
	return std::pair<ubyte_const_iter, ubyte_const_iter>(data_.begin(), data_.end());
}

bool QVPN::Core::DataStructures::CustomPacketLittleEndian::protocol_criteria(UByte protocol)
{
	return (protocol == QVPN::Core::DataStructures::Protocols::TCP) ? false : (protocol == QVPN::Core::DataStructures::Protocols::UDP) ? false : true;
}

UShort QVPN::Core::DataStructures::CustomPacketLittleEndian::get_src_port()
{
	return data_[0] << 8 | data_[1];
}

UShort QVPN::Core::DataStructures::CustomPacketLittleEndian::get_dst_port()
{
	return data_[2] << 8 | data_[3];
}
