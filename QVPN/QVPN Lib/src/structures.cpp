#include "structures.hpp"

using Byte = QVPN::Core::DataStructures::Byte;
using UByte = QVPN::Core::DataStructures::UByte;
using UShort = QVPN::Core::DataStructures::UShort;
using UInt = QVPN::Core::DataStructures::UInt;
using ubyte_const_iter = QVPN::Core::DataStructures::ubyte_const_iter;



QVPN::Core::DataStructures::Ipv4PacketLittleEndian::Ipv4PacketLittleEndian(unsigned char* begin, int size)
{
	parse_packet(begin, begin + size);
}

QVPN::Core::DataStructures::Ipv4PacketLittleEndian::Ipv4PacketLittleEndian(UByte* begin, UByte* end)
{
	parse_packet(begin, end);
}

QVPN::Core::DataStructures::Ipv4PacketLittleEndian::Ipv4PacketLittleEndian(ubyte_const_iter begin, ubyte_const_iter end)
{
	
}

void QVPN::Core::DataStructures::Ipv4PacketLittleEndian::parse_packet(UByte* begin, UByte* end)
{
	memcpy(header_, begin, 20);
	auto start = begin + 20;
	for (auto i = 0; i < get_total_length_impl() - get_header_length_impl(); i++, start += sizeof(UByte))
	{
		data_.push_back((UByte)start);
	}
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_version_impl() const
{
	return header_[0] >> 4;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_header_length_impl() const
{
	return header_[0] & 0xF;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_dscp_impl() const
{
	return header_[1] >> 2;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ecn_impl() const
{
	return header_[1] & 0x3;
}

UShort QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_total_length_impl() const
{
	UShort first = header_[2] << 8;
	UShort total = first | header_[3];
	return total;
}

UShort QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_id_impl() const
{
	UShort first = header_[4] << 8;
	UShort id = first | header_[5];
	return id;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_flags_impl() const
{
	return header_[6] >> 5;
}

UShort QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_offset_impl() const
{
	UShort first = (header_[6] & 0x1F) << 5;
	UShort offset = first | header_[7];
	return offset;
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_ttl_impl() const
{
	return header_[8];
}

UByte QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_protocol_impl() const
{
	return header_[9];
}

UShort QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_checksum_impl() const
{
	UShort first = header_[10] << 8;
	UShort checksum = first | header_[11];
	return checksum;
}

UInt QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_source_impl() const
{
	UInt first = header_[12] << 24;
	UInt second = header_[13] << 16;
	UInt third = header_[14] << 8;
	return first | second | third | header_[15];
}

UInt QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_dest_impl() const
{
	UInt first = header_[16] << 24;
	UInt second = header_[17] << 16;
	UInt third = header_[18] << 8;
	return first | second | third | header_[19];
}

std::pair<ubyte_const_iter, ubyte_const_iter> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_additional_header_impl() const
{
	return std::make_pair<>(additional_header_.cbegin(), additional_header_.cend());
}

std::pair<ubyte_const_iter, ubyte_const_iter> QVPN::Core::DataStructures::Ipv4PacketLittleEndian::get_data_impl() const
{
	return std::make_pair<>(data_.cbegin(), data_.cend());
}
