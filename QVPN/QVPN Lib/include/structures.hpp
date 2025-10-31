#pragma once
#include <string_view>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <lib.hpp>
#include <iterator>
#include <variant>
#include <iostream>


namespace QVPN {
	namespace Core
	{
		namespace DataStructures {


			using Byte = char;
			using UByte = unsigned char;
			using UShort = unsigned short;
			using UInt = unsigned int;
			using ULong = unsigned long long;
			using ubyte_const_iter = std::vector<UByte>::const_iterator;

			enum NetProtocols
			{
				IPv4 = 4,
				IPv6 = 6
			};

			enum TransportProtocols
			{
				TCP = 6,
				UDP = 17
			};

			enum AdapterFlags : ULong {
				DdnsEnabled = 0x1,
				RegisterAdapterSuffix = 0x2,
				DhcpvEnabled = 0x4,
				ReceiveOnly = 0x8,
				NoMulticast = 0x10,
				Ipv6OtherStatefulConfig = 0x20,
				NetbiosOverTcpipEnabled = 0x40,
				Ipv4Enabled = 0x80,
				Ipv6Enabled = 0x100,
				Ipv6ManagedAddressConfigurationSupported = 0x200
			};

			template <class AdapterHandle>
			class Adapter final {
			private:
				std::string adapter_name;
				std::string adapter_desc;
				std::string friendly_name;
				QVPN::Core::IPv4Address address;
				AdapterHandle handle;
				ULong adapter_id;

			public:

				Adapter()
				{
					handle = nullptr;
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname)
				{
					
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, ULong a_id)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), adapter_id(a_id)
				{

				}

				Adapter(std::string_view a_name, std::string_view a_desc, const QVPN::Core::IPv4Address& addr)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_name), address(addr)
				{

				}

				Adapter(std::string_view a_name, std::string_view a_desc, const QVPN::Core::IPv4Address& addr, ULong a_id)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_name), address(addr), adapter_id(a_id)
				{

				}

				Adapter(std::string_view a_name, std::string_view a_desc, const QVPN::Core::IPv4Address& addr, AdapterHandle hnd)
					: Adapter(a_name, a_desc, addr)
				{
					handle = hnd;
				}

				Adapter(std::string_view a_name, std::string_view a_desc, const QVPN::Core::IPv4Address& addr, AdapterHandle hnd, ULong a_id)
					: Adapter(a_name, a_desc, addr)
				{
					handle = hnd;
					adapter_id = a_id;
				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, AdapterHandle a_handle)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), handle(a_handle)
				{

				}

				Adapter(std::string_view a_name, std::string_view a_desc, std::string_view a_fname, AdapterHandle a_handle, ULong a_id)
					: adapter_name(a_name), adapter_desc(a_desc), friendly_name(a_fname), handle(a_handle), adapter_id(a_id)
				{

				}

				void set_handle(const AdapterHandle a_handle)
				{
					handle = a_handle;
				}

				void set_data(std::string_view a_name, std::string_view a_desc, std::string_view a_fname)
				{
					adapter_name = a_name;
					adapter_desc = a_desc;
					friendly_name = a_fname;
				}

				void set_name(std::string_view a_name)
				{
					adapter_name = a_name;
				}

				void set_desc(std::string_view a_desc)
				{
					adapter_desc = a_desc;
				}

				void set_friendly_name(std::string_view a_fname)
				{
					friendly_name = a_fname;
				}

				std::string_view get_name() const
				{
					return adapter_name;
				}

				std::string_view get_desc() const
				{
					return adapter_desc;
				}

				std::string_view get_friendly_name() const
				{
					return friendly_name;
				}


				const AdapterHandle get_handle() const
				{
					return const_cast<AdapterHandle>(handle);
				}

				const QVPN::Core::IPv4Address& get_addr() const
				{
					return address;
				}

				const ULong get_id() const
				{
					return adapter_id;
				}

				~Adapter()
				{

				}


			};


			template<class Ip4PacketLike, class AdapterHandle>
			concept is_adapter_criteria =
				requires (Ip4PacketLike t) {
					{ true };
					{ t.check_criteria(std::declval<const Adapter<AdapterHandle>&>()) } -> std::same_as<bool>;
			};

			template <class AdapterHandle>
			class AdapterList final : public std::vector<Adapter<AdapterHandle>> {

			public:

				template<class U, class AdapterHandle> requires is_adapter_criteria<U, AdapterHandle>
				std::shared_ptr<Adapter<AdapterHandle>> get_default_adapter()
				{
					for (const auto& it : *this)
					{
						if (U::check_criteria(it))
						{
							return std::make_shared<Adapter<AdapterHandle>>(it);
						}
					}
					return nullptr;
				}

				~AdapterList() {}
			};


			template <class PacketImpl>
			concept UnifiedPacketLike =
				requires (PacketImpl t) {

				typename PacketImpl::DataIterator_t;
				typename PacketImpl::ConstDataIterator_t;

					{ t.to_bytes() } -> std::same_as<std::pair<typename PacketImpl::ConstDataIterator_t, typename PacketImpl::ConstDataIterator_t>>;
			};

			template <class IpPacketImpl>
			concept UnifiedIpPacketLike =
				requires (IpPacketImpl t) {

					{ t.get_src() } -> std::same_as<std::pair<const UByte*, const UByte*>>;
					{ t.get_dst() } -> std::same_as<std::pair<const UByte*, const UByte*>>;

					{ t.recalculate_ip_checksum() } -> std::same_as<void>;

			};

			template <class Ip4PacketImpl>
			concept Ip4PacketLike =
				requires (Ip4PacketImpl t) {
					
				typename Ip4PacketImpl::DataIterator_t;
				typename Ip4PacketImpl::ConstDataIterator_t;

					{ Ip4PacketImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
					{ t.get_next_protocol_byte() } -> std::same_as<UByte*>;
					{ t.parse_packet(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;
					{ t.get_ip_version() } -> std::same_as<UByte>;
					{ t.get_ip_header_length() } -> std::same_as<UByte>;
					{ t.get_ip_dscp() } -> std::same_as<UByte>;
					{ t.get_ip_ecn() } -> std::same_as<UByte>;
					{ t.get_ip_total_length() } -> std::same_as<UShort>;
					{ t.get_ip_id() } -> std::same_as<UShort>;
					{ t.get_ip_flags() } -> std::same_as<UByte>;
					{ t.get_ip_offset() } -> std::same_as<UShort>;
					{ t.get_ip_ttl() } -> std::same_as<UByte>;
					{ t.get_ip_checksum() } -> std::same_as<UShort>;
					{ t.get_ip_source() } -> std::same_as<IPv4Address>;
					{ t.get_ip_dest() } -> std::same_as<IPv4Address>;
					{ t.get_ip_additional_header() } -> std::same_as<std::pair<typename Ip4PacketImpl::ConstDataIterator_t, typename Ip4PacketImpl::ConstDataIterator_t>>;
					{ t.ip_to_friendly_view() } -> std::same_as<std::string>;
					

					{ t.set_ip_source(std::declval<const QVPN::Core::IPv4Address&>()) } -> std::same_as<void>;
					{ t.set_ip_dest(std::declval<const QVPN::Core::IPv4Address&>()) } -> std::same_as<void>;

					{ t.set_ip_checksum(std::declval<const UShort>()) } -> std::same_as<void>;

			} && UnifiedIpPacketLike<Ip4PacketImpl> && UnifiedPacketLike<Ip4PacketImpl>;



			class Ipv4PacketLittleEndian {

			private:

				std::vector<UByte> header_;
				UByte* next_protocol_;

			public:

				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

				Ipv4PacketLittleEndian(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				UByte get_ip_version() const;
				UByte get_ip_header_length() const;

				UByte get_ip_dscp() const;
				UByte get_ip_ecn() const;

				UShort get_ip_total_length() const;

				UShort get_ip_id() const;

				UByte  get_ip_flags() const;
				UShort get_ip_offset() const;

				UByte get_ip_ttl() const;
				UByte get_ip_protocol() const;

				UShort get_ip_checksum() const;

				IPv4Address get_ip_source() const;
				IPv4Address get_ip_dest() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_ip_additional_header() const;
				std::string ip_to_friendly_view() const;


				void set_ip_source(const QVPN::Core::IPv4Address& src);
				void set_ip_dest(const QVPN::Core::IPv4Address& dst);

				void set_ip_checksum(const UShort checksum);

				/* Unified Ip Packet implementaion */
				std::pair<const UByte*, const UByte*> get_src() const;
				std::pair<const UByte*, const UByte*> get_dst() const;
				void recalculate_ip_checksum();

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;


			};


			class Ipv4PacketView {

			private:

				UByte* header_;
				const int ip4_header_size_ = 20;
				
				UByte* next_protocol_;

				UByte* additional_header_;
				int add_header_size_ = 0;

			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				Ipv4PacketView(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				UByte get_ip_version() const;
				UByte get_ip_header_length() const;

				UByte get_ip_dscp() const;
				UByte get_ip_ecn() const;

				UShort get_ip_total_length() const;

				UShort get_ip_id() const;

				UByte  get_ip_flags() const;
				UShort get_ip_offset() const;

				UByte get_ip_ttl() const;
				UByte get_ip_protocol() const;

				UShort get_ip_checksum() const;

				IPv4Address get_ip_source() const;
				IPv4Address get_ip_dest() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_ip_additional_header() const;
				std::string ip_to_friendly_view() const;

				
				void set_ip_source(const QVPN::Core::IPv4Address& src);
				void set_ip_dest(const QVPN::Core::IPv4Address& dst);

				void set_ip_checksum(const UShort checksum);

				/* Unified Ip Packet implementaion */
				std::pair<const UByte*, const UByte*> get_src() const;
				std::pair<const UByte*, const UByte*> get_dst() const;
				void recalculate_ip_checksum();

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;


			};

			template <Ip4PacketLike Ip4PacketImpl>
			class Ipv4Packet_ : public Ip4PacketImpl {

			public:

				Ipv4Packet_(UByte* begin, UByte* end)
					: Ip4PacketImpl(begin, end) {}

			};

#pragma pack(push, 1)
			struct TransportIpv4PseudoHeaderBytesBuffer
			{
				UByte data[12];
			};


			struct TransportIpv4PseudoHeaderTypesBuffer
			{
				UInt src;
				UInt dst;
				UByte zero;
				UByte protocol;
				UShort length;
			};
#pragma pack(pop)

			struct TransportIpv4PseudoHeader
			{
				
				UByte data[12] = { 0 };
				/*
				UInt ph_src;
				UInt ph_dst;
				UByte ph_zero;
				UByte ph_protocol;
				UShort ph_length;
				*/
				TransportIpv4PseudoHeader(UInt src, UInt dst, UByte protocol, UShort length);
				TransportIpv4PseudoHeader(IPv4Address& src, IPv4Address& dst, UByte protocol, UShort length);

				std::pair<const UByte*, const UByte*> get_by_bytes() const;
				TransportIpv4PseudoHeaderTypesBuffer get_by_types() const;

				/*
				UInt src;
				UInt dst;
				UByte zero;
				UByte protocol;
				UShort length;
				*/

			};

			template <class TransportImpl>
			concept UnifiedTransportLike =
				requires (TransportImpl t) {

				typename TransportImpl::DataIterator_t;
				typename TransportImpl::ConstDataIterator_t;

					{ t.get_src_port() } -> std::same_as<UShort>;
					{ t.get_dst_port() } -> std::same_as<UShort>;
					{ t.get_transport_length() } -> std::same_as<UShort>;

					{ t.recalculate_transport_checksum(std::declval<const TransportIpv4PseudoHeader&>(), std::declval<typename TransportImpl::ConstDataIterator_t>(), std::declval<typename TransportImpl::ConstDataIterator_t>()) } -> std::same_as<void>;
			};

			template <class TcpImpl>
			concept TcpPacketLike =
				requires (TcpImpl t) {

					{ TcpImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
					{ t.get_next_protocol_byte() } -> std::same_as<UByte*>;
					{ t.parse_packet(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;
					{ t.get_tcp_src_port() } -> std::same_as<UShort>;
					{ t.get_tcp_dst_port() } -> std::same_as<UShort>;
					{ t.get_tcp_seq_number() } -> std::same_as<UInt>;
					{ t.get_tcp_ack_number() } -> std::same_as<UInt>;
					{ t.get_tcp_header_length() } -> std::same_as<UByte>;
					{ t.get_tcp_reserved() } -> std::same_as<UByte>;
					{ t.get_tcp_flags() } -> std::same_as<UByte>;
					{ t.get_tcp_window_size() } -> std::same_as<UShort>;
					{ t.get_tcp_checksum() } -> std::same_as<UShort>;
					{ t.get_tcp_urgent_pointer() } -> std::same_as<UShort>;
					{ t.get_tcp_options() } -> std::same_as<std::pair<typename TcpImpl::ConstDataIterator_t, typename TcpImpl::ConstDataIterator_t>>;
					{ t.protocol_criteria(std::declval<UByte>()) } -> std::same_as<bool>;
					{ t.tcp_to_friendly_view() } -> std::same_as <std::string>;

					{ t.set_tcp_checksum(std::declval<UShort>()) } -> std::same_as<void>;
					

			} && UnifiedTransportLike<TcpImpl> && UnifiedPacketLike<TcpImpl>;



			class TcpPacketLittleEndian
			{
			private:
				std::vector<UByte> header_;
				UByte* next_protocol_;

			public:

				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

				TcpPacketLittleEndian(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				UShort get_tcp_src_port() const;
				UShort get_tcp_dst_port() const;
				UInt get_tcp_seq_number() const;
				UInt get_tcp_ack_number() const;
				UByte get_tcp_header_length() const;
				UByte get_tcp_reserved() const;
				UByte get_tcp_flags() const;
				UShort get_tcp_window_size() const;
				UShort get_tcp_checksum() const;
				UShort get_tcp_urgent_pointer() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tcp_options() const;
				bool protocol_criteria(UByte protocol) const;
				std::string tcp_to_friendly_view() const;

				void set_tcp_checksum(UShort checksum);

				UShort get_src_port() const;
				UShort get_dst_port() const;
				void recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end);
				UShort get_transport_length() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				

			};


			class TcpPacketView
			{
			private:
				UByte* tcp_header_;
				const int tcp_header_size = 20;

				UByte* options_;
				int tcp_options_size = 0;

				UByte* next_protocol_;

			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				TcpPacketView(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				UShort get_tcp_src_port() const;
				UShort get_tcp_dst_port() const;
				UInt get_tcp_seq_number() const;
				UInt get_tcp_ack_number() const;
				UByte get_tcp_header_length() const;
				UByte get_tcp_reserved() const;
				UByte get_tcp_flags() const;
				UShort get_tcp_window_size() const;
				UShort get_tcp_checksum() const;
				UShort get_tcp_urgent_pointer() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tcp_options() const;
				bool protocol_criteria(UByte protocol) const;
				std::string tcp_to_friendly_view() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tcp_header() const;

				void set_tcp_checksum(UShort checksum);

				UShort get_src_port() const;
				UShort get_dst_port() const;
				void recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end);
				UShort get_transport_length() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				

			};


			template <TcpPacketLike TcpImpl>
			class TcpPacket_ : public TcpImpl {
			public:

				TcpPacket_(UByte* begin, UByte* end)
					: TcpImpl(begin, end) {}


			};


			template <class UdpImpl>
			concept UdpPacketLike =
				requires (UdpImpl t) {

					{ UdpImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
					{ t.get_next_protocol_byte() } -> std::same_as<UByte*>;
					{ t.parse_packet(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;
					{ t.get_udp_src_port() } -> std::same_as<UShort>;
					{ t.get_udp_dst_port() } -> std::same_as<UShort>;
					{ t.get_udp_length() } -> std::same_as<UShort>;
					{ t.get_udp_checksum() } -> std::same_as<UShort>;
					{ t.protocol_criteria(std::declval<UByte>()) } -> std::same_as<bool>;

			} && UnifiedTransportLike<UdpImpl> && UnifiedPacketLike<UdpImpl>;



			class UdpPacketLittleEndian
			{
			private:
				std::vector<UByte> header_;
				UByte* next_protocol_;

			public:

				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

				UdpPacketLittleEndian(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				UShort get_udp_src_port() const;
				UShort get_udp_dst_port() const;
				UShort get_udp_length() const;
				UShort get_udp_checksum() const;
				bool protocol_criteria(UByte protocol) const;

				UShort get_src_port() const;
				UShort get_dst_port() const;
				void recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end);
				UShort get_transport_length() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				
			};


			class UdpPacketView
			{
			private:
				UByte* header_;
				const int udp_header_size = 8;

				UByte* next_protocol_;

			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				UdpPacketView(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				UShort get_udp_src_port() const;
				UShort get_udp_dst_port() const;
				UShort get_udp_length() const;
				UShort get_udp_checksum() const;
				bool protocol_criteria(UByte protocol) const;

				UShort get_src_port() const;
				UShort get_dst_port() const;
				void recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end);
				UShort get_transport_length() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				
			};


			template <UdpPacketLike UdpImpl>
			class UdpPacket_ : public UdpImpl {

			public:

				UdpPacket_(UByte* begin, UByte* end)
					: UdpImpl(begin, end) {}


			};


			template <class CustomPacketImpl>
			concept CustomPacketLike =
				requires (CustomPacketImpl t) {
					
				typename CustomPacketImpl::DataIterator_t;
				typename CustomPacketImpl::ConstDataIterator_t;

					{ CustomPacketImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
					{ t.parse_packet(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;
					{ t.get_custom_data() } -> std::same_as<std::pair<typename CustomPacketImpl::ConstDataIterator_t, typename CustomPacketImpl::ConstDataIterator_t>>;
					{ t.protocol_criteria(std::declval<UByte>()) } -> std::same_as<bool>;

			} && UnifiedTransportLike<CustomPacketImpl> && UnifiedPacketLike<CustomPacketImpl>;



			template <class DataPacketImpl>
			concept DataPacketLike = requires (DataPacketImpl t) {

				typename DataPacketImpl::DataIterator_t;
				typename DataPacketImpl::ConstDataIterator_t;

				{ DataPacketImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
				{ t.get_data() } -> std::same_as<std::pair<typename DataPacketImpl::ConstDataIterator_t, typename DataPacketImpl::ConstDataIterator_t>>;
				{ t.set_data(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;

			} && UnifiedPacketLike<DataPacketImpl>;




			class DataPacketLittleEndian
			{
			private:
				std::vector<UByte> data_;

			public:

				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

				DataPacketLittleEndian(UByte* begin, UByte* end);
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_data() const;

				void set_data(UByte* begin, UByte* end);

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};



			class DataPacketView
			{
			private:
				UByte* data_;

				int data_size = 0;

			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				DataPacketView(UByte* begin, UByte* end);
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_data() const;

				void set_data(UByte* begin, UByte* end);

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			template <DataPacketLike DataPacketImpl>
			class DataPacket_ : public DataPacketImpl
			{
			public:
				DataPacket_(UByte* begin, UByte* end)
					: DataPacketImpl(begin, end) {}
			};



			template <class NetLayer>
			concept is_net_layer = Ip4PacketLike<NetLayer>;

			template <class TransportLayer>
			concept is_transport_layer = TcpPacketLike<TransportLayer> || UdpPacketLike<TransportLayer>;

			template <class DataLayer>
			concept is_data_layer = DataPacketLike<DataLayer>;


			template <class FullPacketImpl>
			concept FullPacketLike = is_net_layer<FullPacketImpl> && is_transport_layer<FullPacketImpl> && is_data_layer<FullPacketImpl>;

			template <is_net_layer NetLayer, is_transport_layer TransportLayer, is_data_layer DataLayer>
			class FullPacket : public NetLayer, public TransportLayer, public DataLayer
			{
			private:

			public:

				FullPacket(UByte* begin, UByte* end)
					: NetLayer(begin, end), TransportLayer(NetLayer::get_next_protocol_byte(), end), DataLayer(TransportLayer::get_next_protocol_byte(), end) {}

				void recalculate_checksums()
				{
					NetLayer::recalculate_ip_checksum();
					UShort length = TransportLayer::get_transport_length();
					auto [b, e] = DataLayer::get_data();
					length = length + (e - b);
					auto src = NetLayer::get_ip_source();
					auto dst = NetLayer::get_ip_dest();
					auto pseudo = TransportIpv4PseudoHeader(src, dst, NetLayer::get_ip_protocol(), length);
					TransportLayer::recalculate_transport_checksum(pseudo, b, e);
				}
				
			};


			/* Default packets */
			using Ipv4Packet = Ipv4Packet_<Ipv4PacketLittleEndian>;

			using TcpPacket = TcpPacket_<TcpPacketLittleEndian>;
			using UdpPacket = UdpPacket_<UdpPacketLittleEndian>;

			using DataPacket = DataPacket_<DataPacketLittleEndian>;
			/////////////////////////////////////////////////////////////////
			/* Packets views */
			using Ipv4Packet_View = Ipv4Packet_<Ipv4PacketView>;

			using TcpPacket_View = TcpPacket_<TcpPacketView>;
			using UdpPacket_View = UdpPacket_<UdpPacketView>;

			using DataPacket_View = DataPacket_<DataPacketView>;
			/////////////////////////////////////////////////////////////////
			/* Full default packets */
			using Ipv4TcpPacket = FullPacket<Ipv4Packet, TcpPacket, DataPacket>;
			using Ipv4UdpPacket = FullPacket<Ipv4Packet, UdpPacket, DataPacket>;
			/////////////////////////////////////////////////////////////////

			/* Full packets views */
			using Ipv4TcpPacket_View = FullPacket<Ipv4Packet_View, TcpPacket_View, DataPacket_View>;
			using Ipv4UdpPacket_View = FullPacket<Ipv4Packet_View, UdpPacket_View, DataPacket_View>;
			/////////////////////////////////////////////////////////////////


			// Default specs
			template <>
			class FullPacket<Ipv4Packet, TcpPacket, DataPacket> : public Ipv4Packet, public TcpPacket, public DataPacket
			{
			private:

				using Ipv4Packet::ConstDataIterator_t;
				std::vector<UByte> data_;

			public:

				FullPacket(UByte* begin, UByte* end)
					: Ipv4Packet(begin, end), TcpPacket(Ipv4Packet::get_next_protocol_byte(), end), DataPacket(TcpPacket::get_next_protocol_byte(), end) {}

				std::pair<ConstDataIterator_t, ConstDataIterator_t> bytes()
				{
					auto [b1, e1] = Ipv4Packet::to_bytes();
					std::copy(b1, e1, std::back_inserter(data_));

					auto [b2, e2] = TcpPacket::to_bytes();
					std::copy(b2, e2, std::back_inserter(data_));

					auto [b3, e3] = DataPacket::to_bytes();
					std::copy(b3, e3, std::back_inserter(data_));

					return std::make_pair<>(data_.cbegin(), data_.cend());
				}

				void recalculate_checksums()
				{
					Ipv4Packet::recalculate_ip_checksum();
					UShort length = Ipv4Packet::get_ip_total_length() - (Ipv4Packet::get_ip_header_length() * 4);
					auto [b, e] = DataPacket::get_data();
					//length = length + (e - b);
					auto src = Ipv4Packet::get_ip_source();
					auto dst = Ipv4Packet::get_ip_dest();
					auto pseudo = TransportIpv4PseudoHeader(src, dst, Ipv4Packet::get_ip_protocol(), length);
					TcpPacket::recalculate_transport_checksum(pseudo, b, e);
				}

			};

			template <>
			class FullPacket<Ipv4Packet, UdpPacket, DataPacket> : public Ipv4Packet, public UdpPacket, public DataPacket
			{
			private:

				std::vector<UByte> data_;

			public:

				FullPacket(UByte* begin, UByte* end)
					: Ipv4Packet(begin, end), UdpPacket(Ipv4Packet::get_next_protocol_byte(), end), DataPacket(UdpPacket::get_next_protocol_byte(), end) {}

				std::pair<Ipv4Packet::ConstDataIterator_t, Ipv4Packet::ConstDataIterator_t> bytes()
				{
					auto [b1, e1] = Ipv4Packet::to_bytes();
					std::copy(b1, e1, std::back_inserter(data_));

					auto [b2, e2] = UdpPacket::to_bytes();
					std::copy(b2, e2, std::back_inserter(data_));

					auto [b3, e3] = DataPacket::to_bytes();
					std::copy(b3, e3, std::back_inserter(data_));

					return std::make_pair<>(data_.cbegin(), data_.cend());
				}

				void recalculate_checksums()
				{
					Ipv4Packet::recalculate_ip_checksum();
					UShort length = Ipv4Packet::get_ip_total_length() - (Ipv4Packet::get_ip_header_length() * 4);
					auto [b, e] = DataPacket::get_data();
					//length = length + (e - b);
					auto src = Ipv4Packet::get_ip_source();
					auto dst = Ipv4Packet::get_ip_dest();
					auto pseudo = TransportIpv4PseudoHeader(src, dst, Ipv4Packet::get_ip_protocol(), length);
					UdpPacket::recalculate_transport_checksum(pseudo, b, e);
				}

			};



			// View specs
			template <>
			class FullPacket<Ipv4Packet_View, TcpPacket_View, DataPacket_View> : public Ipv4Packet_View, public TcpPacket_View, public DataPacket_View
			{
			private:

				using Ipv4PacketView::ConstDataIterator_t;

			public:

				FullPacket(UByte* begin, UByte* end)
					: Ipv4Packet_View(begin, end), TcpPacket_View(Ipv4Packet_View::get_next_protocol_byte(), end), DataPacket_View(TcpPacket_View::get_next_protocol_byte(), end) {}

				std::pair<ConstDataIterator_t, ConstDataIterator_t> bytes()
				{
					auto [b1, e1] = Ipv4Packet_View::to_bytes();
					auto [b2, e2] = TcpPacket_View::to_bytes();
					auto [b3, e3] = DataPacket_View::to_bytes();
					return std::make_pair<>(b1, e3);
				}

				std::pair<bool, std::string> compare_bytes(ConstDataIterator_t begin, ConstDataIterator_t end)
				{
					auto [b1, e1] = Ipv4Packet_View::to_bytes();
					auto [b2, e2] = TcpPacket_View::to_bytes();
					auto [b3, e3] = DataPacket_View::to_bytes();
					
					auto d1 = std::distance(begin, end);
					auto d2 = std::distance(b1, e3);

					if (d1 != d2)
						return std::make_pair<>(false, "packet size doesnt equal");
					
					bool res = true;
					auto ip_size = std::distance(b1, e1);
					

					for (auto i = 0; i < ip_size ; i++)
					{
						if (b1[i] != begin[i])
							return std::make_pair<>(false, "ip headers error");
					}

					auto tcp_start = begin + ip_size;
					auto tcp_size = std::distance(b2, e2);
					for (auto i = 0; i < tcp_size; i++)
					{
						if (b2[i] != tcp_start[i])
							return std::make_pair<>(false, "tcp header error");
					}

					auto data_start = tcp_start + tcp_size;
					auto data_size = std::distance(b3, e3);
					for (auto i = 0; i < data_size; i++)
					{
						if (b3[i] != data_start[i])
							return std::make_pair<>(false, "data error");
					}

					return std::make_pair<>(true, "All data equal");
				}

				void recalculate_checksums()
				{
					Ipv4Packet_View::recalculate_ip_checksum();
					UShort length = Ipv4Packet_View::get_ip_total_length() - (Ipv4Packet_View::get_ip_header_length() * 4);
					auto [b, e] = DataPacket_View::get_data();
					//length = length + (e - b);
					auto src = Ipv4Packet_View::get_ip_source();
					auto dst = Ipv4Packet_View::get_ip_dest();
					auto pseudo = TransportIpv4PseudoHeader(src, dst, Ipv4Packet_View::get_ip_protocol(), length);
					TcpPacket_View::recalculate_transport_checksum(pseudo, b, e);
				}

			};

			template <>
			class FullPacket<Ipv4Packet_View, UdpPacketView, DataPacket_View> : public Ipv4Packet_View, public UdpPacketView, public DataPacket_View
			{
			private:

				using Ipv4PacketView::ConstDataIterator_t;

			public:

				FullPacket(UByte* begin, UByte* end)
					: Ipv4Packet_View(begin, end), UdpPacketView(Ipv4Packet_View::get_next_protocol_byte(), end), DataPacket_View(UdpPacketView::get_next_protocol_byte(), end) {}

				std::pair<ConstDataIterator_t, ConstDataIterator_t> bytes()
				{
					auto [b1, e1] = Ipv4Packet_View::to_bytes();
					auto [b2, e2] = UdpPacketView::to_bytes();
					auto [b3, e3] = DataPacket_View::to_bytes();
					return std::make_pair<>(b1, e3);
				}

				void recalculate_checksums()
				{
					Ipv4Packet_View::recalculate_ip_checksum();
					UShort length = UdpPacketView::get_transport_length();
					auto [b, e] = DataPacket_View::get_data();
					length = length + (e - b);
					auto src = Ipv4Packet_View::get_ip_source();
					auto dst = Ipv4Packet_View::get_ip_dest();
					auto pseudo = TransportIpv4PseudoHeader(src, dst, Ipv4Packet_View::get_ip_protocol(), length);
					UdpPacketView::recalculate_transport_checksum(pseudo, b, e);
				}

			};



			// Default instances
			template class FullPacket<Ipv4Packet, TcpPacket, DataPacket>;
			template class FullPacket<Ipv4Packet, UdpPacket, DataPacket>;

			// View instances
			template class FullPacket<Ipv4Packet_View, TcpPacket_View, DataPacket_View>;
			template class FullPacket<Ipv4Packet_View, UdpPacket_View, DataPacket_View>;


		}
	}
}

