#include "structures.hpp"
#include <sstream>
#include <iostream>
#include <winsock.h>

using Byte = QVPN::Core::DataStructures::Byte;
using UByte = QVPN::Core::DataStructures::UByte;
using UShort = QVPN::Core::DataStructures::UShort;
using UInt = QVPN::Core::DataStructures::UInt;
using ubyte_const_iter = QVPN::Core::DataStructures::ubyte_const_iter;

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

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::set_ip_source(const QVPN::Core::IPv4Address& src)
{
	constexpr auto ip_addr_size = 4;
	constexpr auto ip_start = 12;
	auto temp = src.to_bytes();
	for (auto i = ip_start, j = 0; i < ip_start + ip_addr_size; i++, j++)
	{
		header_[i] = temp->at(j);
	}
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::set_ip_dest(const QVPN::Core::IPv4Address& dst)
{
	constexpr auto ip_addr_size = 4;
	constexpr auto ip_start = 16;
	auto temp = dst.to_bytes();
	for (auto i = ip_start, j = 0; i < ip_start + ip_addr_size; i++, j++)
	{
		header_[i] = temp->at(j);
	}
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::set_ip_checksum(const UShort checksum)
{
	header_[10] = checksum >> 8 & 0xFF;
	header_[11] = checksum & 0xFF;
}

std::pair<const UByte*, const UByte*> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_src() const
{
	return std::make_pair<>(&header_[12], &header_[15]);
}

std::pair<const UByte*, const UByte*> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_dst() const
{
	return std::make_pair<>(&header_[16], &header_[19]);
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

	res = ~((sum >> 16) + (sum & 0xFFFF));
	set_ip_checksum(res);
}

QVPN::Core::DataStructures::TcpPacketLittleEndian::TcpPacketLittleEndian(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::TcpPacketLittleEndian::parse_packet(UByte* begin, UByte* end)
{
	std::copy(begin, begin + default_tcp_size, std::back_inserter(header_));

	auto start = begin + default_tcp_size;
	auto _end = start + (get_tcp_header_length() * bytes_in_quartet);

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
	return (protocol == QVPN::Core::DataStructures::TransportProtocols::TCP) ? true : false;
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

void QVPN::Core::DataStructures::TcpPacketLittleEndian::recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end)
{
	unsigned int sum = 0;
	UShort res = 0;

	auto [b, e] = pseudo_header.get_by_bytes();

	// pseudo-header checksum
	for (auto i = b; i < e; i += 2)
	{
		UShort temp = *b << 8 | *(b + 1);
		sum += temp;
	}

	// tcp header checksum
	for (int i = 0; i < header_.size(); i += 2) {
		UShort temp = header_[i] << 8 | header_[i + 1];
		sum += temp;
	}
	sum -= get_tcp_checksum();

	// data checksum
	for (auto i = begin; i < end; i += 2) {
		UShort temp = *i << 8 | *(i + 1);
		sum += temp;
	}

	res = ~((sum >> 16) + (sum & 0xFFFF));
	set_tcp_checksum(res);
}

UShort QVPN::Core::DataStructures::TcpPacketLittleEndian::get_transport_length() const
{
	return get_tcp_header_length() * bytes_in_quartet;
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
	return (protocol == QVPN::Core::DataStructures::TransportProtocols::UDP) ? true : false;
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

void QVPN::Core::DataStructures::UdpPacketLittleEndian::recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end)
{
}

UShort QVPN::Core::DataStructures::UdpPacketLittleEndian::get_transport_length() const
{
	return get_udp_length() * bytes_in_quartet;
}


QVPN::Core::DataStructures::DataPacketLittleEndian::DataPacketLittleEndian(UByte* begin, UByte* end)
{
	std::copy(begin, end, std::back_inserter(data_));
}

std::pair<QVPN::Core::DataStructures::DataPacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::DataPacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::DataPacketLittleEndian::get_data() const
{
	return std::make_pair<>(data_.cbegin(), data_.cend());
}

void QVPN::Core::DataStructures::DataPacketLittleEndian::set_data(UByte* begin, UByte* end)
{
}

std::pair<QVPN::Core::DataStructures::DataPacketLittleEndian::ConstDataIterator_t, QVPN::Core::DataStructures::DataPacketLittleEndian::ConstDataIterator_t> QVPN::Core::DataStructures::DataPacketLittleEndian::to_bytes() const
{
	return std::make_pair<>(data_.cbegin(), data_.cend());
}

QVPN::Core::DataStructures::Ipv4PacketView::Ipv4PacketView(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

void QVPN::Core::DataStructures::Ipv4PacketView::parse_packet(UByte* begin, UByte* end)
{
	header_ = begin;

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

UByte QVPN::Core::DataStructures::Ipv4PacketView::get_ip_version() const
{
	return header_[0] >> 4;
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

UByte QVPN::Core::DataStructures::Ipv4PacketView::get_ip_protocol() const
{
	return header_[9];
}

UShort QVPN::Core::DataStructures::Ipv4PacketView::get_ip_checksum() const
{
	UShort first = header_[10] << 8;
	UShort checksum = first | header_[11];
	return checksum;
}

UInt QVPN::Core::DataStructures::Ipv4PacketView::get_ip_source() const
{
	UInt first = header_[12] << 24;
	UInt second = header_[13] << 16;
	UInt third = header_[14] << 8;
	return first | second | third | header_[15];
}

UInt QVPN::Core::DataStructures::Ipv4PacketView::get_ip_dest() const
{
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

void QVPN::Core::DataStructures::Ipv4PacketView::set_ip_source(const QVPN::Core::IPv4Address& src)
{
	constexpr auto ip_addr_size = 4;
	constexpr auto ip_start = 12;
	auto temp = src.to_bytes();
	for (auto i = ip_start, j = 0; i < ip_start + ip_addr_size; i++, j++)
	{
		header_[i] = temp->at(j);
	}
}

void QVPN::Core::DataStructures::Ipv4PacketView::set_ip_dest(const QVPN::Core::IPv4Address& dst)
{
	constexpr auto ip_addr_size = 4;
	constexpr auto ip_start = 16;
	auto temp = dst.to_bytes();
	for (auto i = ip_start, j = 0; i < ip_start + ip_addr_size; i++, j++)
	{
		header_[i] = temp->at(j);
	}
}

void QVPN::Core::DataStructures::Ipv4PacketView::set_ip_checksum(const UShort checksum)
{
	header_[10] = checksum >> 8 & 0xFF;
	header_[11] = checksum & 0xFF;
}

std::pair<const UByte*, const UByte*> QVPN::Core::DataStructures::Ipv4PacketView::get_src() const
{
	return std::make_pair<>(&header_[12], &header_[15]);
}

std::pair<const UByte*, const UByte*> QVPN::Core::DataStructures::Ipv4PacketView::get_dst() const
{
	return std::make_pair<>(&header_[16], &header_[19]);
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

	res = ~((sum >> 16) + (sum & 0xFFFF));
	set_ip_checksum(res);
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
	header_ = begin;

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
	return header_[0] << 8 | header_[1];
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_tcp_dst_port() const
{
	return header_[2] << 8 | header_[3];
}

UInt QVPN::Core::DataStructures::TcpPacketView::get_tcp_seq_number() const
{
	return header_[4] << 24 | header_[5] << 16 | header_[6] << 8 | header_[7];
}

UInt QVPN::Core::DataStructures::TcpPacketView::get_tcp_ack_number() const
{
	return header_[8] << 24 | header_[9] << 16 | header_[10] << 8 | header_[11];
}

UByte QVPN::Core::DataStructures::TcpPacketView::get_tcp_header_length() const
{
	return header_[12] >> 4;
}

UByte QVPN::Core::DataStructures::TcpPacketView::get_tcp_reserved() const
{
	return header_[12] & 0xF;
}

UByte QVPN::Core::DataStructures::TcpPacketView::get_tcp_flags() const
{
	return header_[13];
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_tcp_window_size() const
{
	return header_[14] << 8 | header_[15];
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_tcp_checksum() const
{
	return header_[16] << 8 | header_[17];
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_tcp_urgent_pointer() const
{
	return header_[18] << 8 | header_[19];
}

std::pair<QVPN::Core::DataStructures::TcpPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::TcpPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::TcpPacketView::get_tcp_options() const
{
	return std::make_pair<>(options_, options_ + tcp_options_size);
}

bool QVPN::Core::DataStructures::TcpPacketView::protocol_criteria(UByte protocol) const
{
	return (protocol == QVPN::Core::DataStructures::TransportProtocols::TCP) ? true : false;
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
	return std::make_pair<>(header_, header_ + tcp_header_size);
}

void QVPN::Core::DataStructures::TcpPacketView::set_tcp_checksum(UShort checksum)
{
	header_[16] = checksum >> 8 & 0xFF;
	header_[17] = checksum & 0xFF;
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
	return std::make_pair<>(header_, options_ + tcp_options_size);
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
		UShort temp = static_cast<UShort>(*i << 8 | *(i + 1));
		sum += temp;
	}


	// tcp header checksum
	for (int i = 0; i < tcp_header_size; i+=2) {
		UShort temp = static_cast<UShort>(header_[i] << 8 | header_[i + 1]);
		sum += temp;
	}


	// tcp header options checksum
	for (int i = 0; i < tcp_options_size; i+=2) {
		UShort temp = static_cast<UShort>(options_[i] << 8 | options_[i + 1]);
		sum += temp;
	}

	auto data_size = std::distance(begin, end);
	// data checksum
	for (auto i = begin; i < end; i++) {
		UShort temp;
		if (i + 1 < end)
		{
			temp = *i << 8 | *(i + 1);
			i++;
		}
		else
		{
			temp = *i << 8;
		}
		sum += temp;
	}

	while (sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
		std::cout << "sum :" << sum << std::endl;
	}
		
	res = static_cast<UShort>(sum);
	std::cout << "res: " << res << std::endl;
	res = htons(~res);
	std::cout << "~res: " << res << std::endl;
	set_tcp_checksum(res);
}

UShort QVPN::Core::DataStructures::TcpPacketView::get_transport_length() const
{
	return get_tcp_header_length() * bytes_in_quartet;
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
	return (protocol == QVPN::Core::DataStructures::TransportProtocols::UDP) ? true : false;
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

void QVPN::Core::DataStructures::UdpPacketView::recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end)
{
}

UShort QVPN::Core::DataStructures::UdpPacketView::get_transport_length() const
{
	return get_udp_length() * bytes_in_quartet;
}


QVPN::Core::DataStructures::DataPacketView::DataPacketView(UByte* begin, UByte* end)
{
	data_ = begin;
	data_size = end - begin;
}

std::pair<QVPN::Core::DataStructures::DataPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::DataPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::DataPacketView::get_data() const
{
	return std::make_pair<>(data_, data_ + data_size);
}

void QVPN::Core::DataStructures::DataPacketView::set_data(UByte* begin, UByte* end)
{
	std::copy(begin, end, data_);
	//data_ = begin;
	//data_size = end - begin;
}

std::pair<QVPN::Core::DataStructures::DataPacketView::ConstDataIterator_t, QVPN::Core::DataStructures::DataPacketView::ConstDataIterator_t> QVPN::Core::DataStructures::DataPacketView::to_bytes() const
{
	return std::make_pair<>(data_, data_ + data_size);
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
	/*
	// src
	data[0] = src & 0xFF;
	data[1] = src >> 8 & 0xFF;
	data[2] = src >> 16 & 0xFF;
	data[3] = src >> 24 & 0xFF;

	//dst
	data[4] = dst & 0xFF;
	data[5] = dst >> 8 & 0xFF;
	data[6] = dst >> 16 & 0xFF;
	data[7] = dst >> 24 & 0xFF;

	//zero
	data[8] = 0;

	// proto
	data[9] = protocol;

	//length
	data[10] = length & 0xFF;
	data[11] = length >> 8 & 0xFF;
	*/
	
	std::memcpy(data, &src, addr_size);
	std::memcpy(data + addr_size, &dst, addr_size);
	data[8] = 0;
	data[9] = protocol;
	std::memcpy(&data[10], &length, length_size);
	
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
