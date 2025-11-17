#pragma once
#include <string_view>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <qvpn_lib.hpp>
#include <iterator>
#include <variant>
#include <iostream>
#include <unordered_map>
#include "qvpn_driver.hpp"
#include <random>
#include <ctime>
#include <algorithm>



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


			enum QVPNCharset
			{
				CP866 = 866,
				CP1251 = 1251,
				UTF8 = 65001,
				UNKNOWN = 9999
			};

			// only ip4 and ip6
			enum NetProtocols
			{
				IPv4 = 4,
				IPv6 = 6
			};

			// only tcp and udp
			enum TransportProtocols
			{
				TCP = 6,
				UDP = 17
			};

			// not all http methods
			enum class HttpRequestType
			{
				HEAD = 0,
				GET = 1,
				POST = 2,
				PUT = 3,
				DELETE_REQUEST = 4,
				CONNECT = 5,
				OPTIONS,
				TRACE,
				UNKNOWN = 9999
			};

			enum class HttpVersion
			{
				HTTP1 = 0,
				HTTP1_1 = 1,
				HTTP2 = 2,
				HTTP3 = 3,
				UNKNOWN = 9999
			};

			enum class HttpResponseStatus
			{
				SWITCH_PROTOCOLS = 101,

				OK = 200,
				CREATED = 201,

				MOVED_PERMANENTLY = 301,
				FOUND = 302,
				NOT_MODIFIED = 304,

				BAD_REQUEST = 400,
				FORBIDDEN = 403,
				NOT_FOUND = 404,

				INTERNAL_SERVER_ERROR = 500,
				NOT_IMPLEMENTED = 501,
				HTTP_VERSION_NOT_SUPPORTED = 505,

				UNKNOWN = 9999

			};

			enum class HttpContentType
			{
				TEXT_HTML = 0,
				UNKNOWN = 9999
			};

			enum class HttpConnectionType
			{
				KEEP_ALIVE = 0,
				CLOSED = 1,
				UNKNOWN = 9999
			};

			enum class HttpUserAgent
			{
				MOZILLA = 0,
				APPLE_WEB_KIT = 1,
				CHROME = 2,
				SAFARI = 3,
				UKNOWN = 9999
			};


			enum TLSRecordType : UByte {
				CHANGE_CIPHER_SPEC = 20,
				ALERT = 21,
				HANDSHAKE = 22,
				APPLICATION_DATA = 23
			};


			enum TLSHandshakeType : UByte {
				CLIENT_HELLO = 1,
				SERVER_HELLO = 2,
				NEW_SESSION_TICKET = 4,
				CERTIFICATE = 11,
				SERVER_KEY_EXCHANGE = 12,
				CERTIFICATE_REQUEST = 13,
				SERVER_HELLO_DONE = 14,
				CERTIFICATE_VERIFY = 15,
				CLIENT_KEY_EXCHANGE = 16,
				FINISHED = 20
			};

			// TLS версии
			enum TLSProtocolVersion : UShort {
				SSL30 = 0x0300,
				TLS10 = 0x0301,
				TLS11 = 0x0302,
				TLS12 = 0x0303,
				TLS13 = 0x0304
			};

			// Cipher Suite
			enum TLSCipherSuite : UShort {
				TLS_AES_128_GCM_SHA256 = 0x1301,
				TLS_AES_256_GCM_SHA384 = 0x1302,
				TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
			};

			// Compression Method
			enum TLSCompressionMethod : UByte {
				NULL_COMPRESSION = 0x00
			};

			// Extension types
			enum TLSExtensionType : UShort {
				SERVER_NAME = 0,
				SUPPORTED_GROUPS = 10,
				SIGNATURE_ALGORITHMS = 13,
				ALPN = 16,
				KEY_SHARE = 40,
				SUPPORTED_VERSIONS = 43
			};

			enum TLSSNIRecordType : UByte {
				HOST_NAME = 0,
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

			}&& UnifiedIpPacketLike<Ip4PacketImpl>&& UnifiedPacketLike<Ip4PacketImpl>;


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
					: Ip4PacketImpl(begin, end) {
				}

			};

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


			}&& UnifiedTransportLike<TcpImpl>&& UnifiedPacketLike<TcpImpl>;



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
					: TcpImpl(begin, end) {
				}


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

			}&& UnifiedTransportLike<UdpImpl>&& UnifiedPacketLike<UdpImpl>;



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
					: UdpImpl(begin, end) {
				}


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

			}&& UnifiedTransportLike<CustomPacketImpl>&& UnifiedPacketLike<CustomPacketImpl>;



			template <class DataPacketImpl>
			concept DataPacketLike = requires (DataPacketImpl t) {

				typename DataPacketImpl::DataIterator_t;
				typename DataPacketImpl::ConstDataIterator_t;

				{ DataPacketImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
				{ t.get_data() } -> std::same_as<std::pair<typename DataPacketImpl::ConstDataIterator_t, typename DataPacketImpl::ConstDataIterator_t>>;
				{ t.set_data(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;

			}&& UnifiedPacketLike<DataPacketImpl>;




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
					: DataPacketImpl(begin, end) {
				}
			};


			template <class HttpImpl>
			concept UnifiedHttpPacketLike =
				requires (HttpImpl t) {
					{ t.get_http_version() } -> std::same_as<std::pair<HttpVersion, std::string>>;
			};


			template <class HttpRequestImpl>
			concept HttpRequestPacketLike =
				requires (HttpRequestImpl t, BaseTypes::UByte begin, BaseTypes::UByte end) {

					{ t.get_http_request() } -> std::same_as<std::string>;
					{ t.get_http_request_header() } -> std::same_as<std::string>;
					{ t.get_http_request_body() } -> std::same_as<std::string>;
					{ t.get_http_request_type() } -> std::same_as<std::pair<HttpRequestType, std::string>>;
					{ t.get_http_request_host() } -> std::same_as<std::string>;
					{ t.get_http_request_connection_type() } -> std::same_as<std::pair<HttpConnectionType, std::string>>;
					{ t.get_http_request_user_agent() } -> std::same_as<std::pair<HttpUserAgent, std::string>>;



					{ t.get_http_request_header_bytes() } -> std::same_as<std::pair<typename HttpRequestImpl::ConstDataIterator_t, typename HttpRequestImpl::ConstDataIterator_t>>;
					{ t.get_http_request_body_bytes() } -> std::same_as<std::pair<typename HttpRequestImpl::ConstDataIterator_t, typename HttpRequestImpl::ConstDataIterator_t>>;

			}&& UnifiedHttpPacketLike<HttpRequestImpl>&& UnifiedPacketLike<HttpRequestImpl>;


			template <class HttpResponseImpl>
			concept HttpResponsePacketLike =
				requires (HttpResponseImpl t, BaseTypes::UByte begin, BaseTypes::UByte end) {

					{ t.get_http_response() } -> std::same_as<std::string>;
					{ t.get_http_response_header() } -> std::same_as<std::string>;
					{ t.get_http_response_body() } -> std::same_as<std::string>;
					{ t.get_http_response_status() } -> std::same_as<std::pair<HttpResponseStatus, std::string>>;
					{ t.get_http_response_content_type() } -> std::same_as<std::pair<HttpContentType, std::string>>;
					{ t.get_http_response_charset() } -> std::same_as<std::pair<QVPNCharset, std::string>>;
					{ t.get_http_response_content_length() } -> std::same_as<BaseTypes::UInt>;
					{ t.get_http_response_server() } -> std::same_as <std::string>;


					{ t.get_http_response_header_bytes() } -> std::same_as<std::pair<typename HttpResponseImpl::ConstDataIterator_t, typename HttpResponseImpl::ConstDataIterator_t>>;
					{ t.get_http_response_body_bytes() } -> std::same_as<std::pair<typename HttpResponseImpl::ConstDataIterator_t, typename HttpResponseImpl::ConstDataIterator_t>>;

			}&& UnifiedHttpPacketLike<HttpResponseImpl>&& UnifiedPacketLike<HttpResponseImpl>;



			class Http1PacketRequestLittleEndian
			{
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:
				std::vector<UByte> data_;

				std::string_view to_string_view() const;
			public:
				/* Unified IP Packet implementaion */
				std::pair<HttpVersion, std::string> get_http_version() const;

				std::string get_http_request() const;
				std::string get_http_request_header() const;
				std::string get_http_request_body() const;
				std::pair<HttpRequestType, std::string> get_http_request_type() const;
				std::string get_http_request_host() const;
				std::pair<HttpConnectionType, std::string> get_http_request_connection_type() const;
				std::pair<HttpUserAgent, std::string> get_http_request_user_agent() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_http_request_header_bytes() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_http_request_body_bytes() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class Http1PacketRequestView
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt data_size_;

				std::string_view to_string_view() const;
			public:
				/* Unified IP Packet implementaion */
				std::pair<HttpVersion, std::string> get_http_version() const;

				std::string get_http_request() const;
				std::string get_http_request_header() const;
				std::string get_http_request_body() const;
				std::pair<HttpRequestType, std::string> get_http_request_type() const;
				std::string get_http_request_host() const;
				std::pair<HttpConnectionType, std::string> get_http_request_connection_type() const;
				std::pair<HttpUserAgent, std::string> get_http_request_user_agent() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_http_request_header_bytes() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_http_request_body_bytes() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class Http1PacketResponseLittleEndian
			{
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:
				std::vector<UByte> data_;

				std::string_view to_string_view() const;
			public:
				/* Unified IP Packet implementaion */
				std::pair<HttpVersion, std::string> get_http_version() const;

				std::string get_http_response() const;
				std::string get_http_response_header() const;
				std::string get_http_response_body() const;
				std::pair<HttpResponseStatus, std::string> get_http_response_status() const;
				std::pair<HttpContentType, std::string> get_http_response_content_type() const;
				std::pair<QVPNCharset, std::string> get_http_response_charset() const;
				UInt get_http_response_content_length() const;
				std::string get_http_response_server() const;


				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_http_response_header_bytes() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_http_response_body_bytes() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			class Http1PacketResponseView
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt data_size_;

				std::string_view to_string_view() const;
			public:
				/* Unified IP Packet implementaion */
				std::pair<HttpVersion, std::string> get_http_version() const;

				std::string get_http_response() const;
				std::string get_http_response_header() const;
				std::string get_http_response_body() const;
				std::pair<HttpResponseStatus, std::string> get_http_response_status() const;
				std::pair<HttpContentType, std::string> get_http_response_content_type() const;
				std::pair<QVPNCharset, std::string> get_http_response_charset() const;
				UInt get_http_response_content_length() const;
				std::string get_http_response_server() const;


				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_http_response_header_bytes() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_http_response_body_bytes() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			template <class HttpRequestImpl>
				requires HttpRequestPacketLike<HttpRequestImpl>
			class HttpRequestPacket : public HttpRequestImpl
			{

			};

			template <class HttpResponseImpl>
				requires HttpResponsePacketLike<HttpResponseImpl>
			class HttpResponsePacket : public HttpResponseImpl
			{

			};


			// Структура Random (32 байта)
			class TLSRandomLittleEndian final {

			public:
				using DataIterator_t = std::array<UByte, 32>::iterator;
				using ConstDataIterator_t = std::array<UByte, 32>::const_iterator;

			private:
				std::array<UByte, 32> random_bytes_;

			public:

				template<std::random_access_iterator Iter>
				TLSRandomLittleEndian(Iter first, Iter last)
				{
					std::copy(first, first + 32, std::back_inserter(random_bytes_));
				}

				UShort get_tls_random_full_length() const;
				UInt get_tls_unix_time() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_random_bytes() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			class TLSRandomView final {

			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				UByte* random_bytes_;
				UInt size_ = 32;

			public:

				template<std::random_access_iterator Iter>
				TLSRandomView(Iter first, Iter last)
				{
					random_bytes_ = first;
					size_ = std::distance(first, first + 32);
				}

				UShort get_tls_random_full_length() const;
				UInt get_tls_unix_time() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_random_bytes() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			// Session ID
			class TLSSessionIDLittleEndian final {
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:

				std::vector<UByte> id_;

			public:

				template<std::random_access_iterator Iter>
				TLSSessionIDLittleEndian(Iter first, Iter last)
				{
					auto length = first[0];
					std::copy(first, first + length + 1, std::back_inserter(id_));
				}

				UShort get_tls_id_full_length() const;
				UByte get_tls_id_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_id();

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSSessionIDView final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				UByte* data_;
				UInt size_;

			public:

				template<std::random_access_iterator Iter>
				TLSSessionIDView(Iter first, Iter last)
				{
					data_ = first;
					auto length = get_tls_id_full_length();
					size_ = std::distance(first, first + length);
				}

				UInt get_tls_id_full_length() const;
				UByte get_tls_id_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_id();

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSCipherSuitLittleEndian final {
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:
				std::vector<UByte> ciphers_;

			public:

				template<std::random_access_iterator Iter>
				TLSCipherSuitLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[0] << 8 | first[1]);
					std::copy(first, first + length + 2, std::back_inserter(ciphers_));
				}

				UShort get_tls_ciphers_full_length() const;
				UShort get_tls_ciphers_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_cipher_suites() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSCipherSuitView final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt size_;

			public:

				template<std::random_access_iterator Iter>
				TLSCipherSuitView(Iter first, Iter last)
				{
					data_ = first;
					size_ = std::distance(first, first + get_tls_ciphers_full_length());
				}

				UShort get_tls_ciphers_full_length() const;
				UShort get_tls_ciphers_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_cipher_suites() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSCompressionLittleEndian final {
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:
				std::vector<UByte> compressions_;

			public:
				template<std::random_access_iterator Iter>
				TLSCompressionLittleEndian(Iter first, Iter last)
				{
					auto length = first[0];
					std::copy(first, first + length + 1, std::back_inserter(compressions_));
				}

				UShort get_tls_compressions_full_length() const;
				UByte get_tls_compressions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_compressions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSCompressionView final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt size_;

			public:
				template<std::random_access_iterator Iter>
				TLSCompressionView(Iter first, Iter last)
				{
					data_ = first;
					size_ = std::distance(first, first + get_tls_compressions_full_length());
				}

				UShort get_tls_compressions_full_length() const;
				UByte get_tls_compressions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_compressions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			// Структура для расширений
			class TLSExtensionLittleEndian final {
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:
				std::vector<UByte> data_;

			public:

				template<std::random_access_iterator Iter>
				TLSExtensionLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[2] << 8 | first[3]);
					std::copy(first, first + length + 4, std::back_inserter(data_));
				}

				UShort get_tls_ext_full_length() const;
				TLSExtensionType get_tls_ext_type() const;
				UShort get_tls_ext_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_ext_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSExtensionView final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt size_;

			public:

				template<std::random_access_iterator Iter>
				TLSExtensionView(Iter first, Iter last)
				{
					data_ = first;
					size_ = std::distance(first, first + get_tls_ext_full_length());
				}

				UShort get_tls_ext_full_length() const;
				TLSExtensionType get_tls_ext_type() const;
				UShort get_tls_ext_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_ext_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;

			};

			class TLSExtensionsLittleEndian final
			{
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:
				std::vector<UByte> extensions_;

			public:

				template<std::random_access_iterator Iter>
				TLSExtensionsLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[0] << 8 | first[1]);
					std::copy(first, first + length + 2, std::back_inserter(extensions_));
				}

				UShort get_tls_extensions_full_length() const;
				UShort get_tls_extensions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_extensions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			class TLSExtensionsView final
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt size_;

			public:

				template<std::random_access_iterator Iter>
				TLSExtensionsView(Iter first, Iter last)
				{
					data_ = first;
					size_ = std::distance(first, first + get_tls_extensions_full_length());
				}

				UShort get_tls_extensions_full_length() const;
				UShort get_tls_extensions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_extensions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			// Supported Versions Extension
			class TLSSupportedVersionsExtensionLittleEndian final {
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:

				std::vector<UByte> versions_;

			public:
				template<std::random_access_iterator Iter>
				TLSSupportedVersionsExtensionLittleEndian(Iter first, Iter last)
				{
					auto length = first[0];
					std::copy(first, first + length + 1, std::back_inserter(versions_));
				}

				UShort get_tls_versions_full_length() const;
				UByte get_tls_versions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_supported_versions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSSupportedVersionsExtensionView final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				UByte* data_;
				UInt size_;

			public:
				template<std::random_access_iterator Iter>
				TLSSupportedVersionsExtensionView(Iter first, Iter last)
				{
					data_ = first;
					auto length = get_tls_versions_full_length();
					size_ = std::distance(first, first + length);
				}

				UShort get_tls_versions_full_length() const;
				UByte get_tls_versions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_supported_versions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			// Key Share Entry
			class TLSKeyShareEntryLittleEndian final {
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:

				std::vector<UByte> key_exchange_;

			public:

				template<std::random_access_iterator Iter>
				TLSKeyShareEntryLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[2] << 8 | first[3]);
					std::copy(first, first + length + 4, std::back_inserter(key_exchange_));
				}

				UShort get_tls_key_share_group_full_length() const;
				UShort get_tls_keyshare_group() const;
				UShort get_tls_key_exchange_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_key_exchange() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSKeyShareEntryView final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				UByte* data_;
				UInt size_;

			public:

				template<std::random_access_iterator Iter>
				TLSKeyShareEntryView(Iter first, Iter last)
				{
					data_ = first;
					auto length = get_tls_key_share_group_full_length();
					size_ = std::distance(first, first + length);
				}

				UShort get_tls_key_share_group_full_length() const;
				UShort get_tls_keyshare_group() const;
				UShort get_tls_key_exchange_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_key_exchange() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			// Key Share Extension
			class TLSKeyShareClientHelloLittleEndian final {
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:

				std::vector<UByte> client_shares_;

			public:
				template<std::random_access_iterator Iter>
				TLSKeyShareClientHelloLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[0] << 8 | first[1]);
					std::copy(first, first + length + 2, std::back_inserter(client_shares_));
				}

				UShort get_tls_key_share_full_length() const;
				UShort get_tls_key_share_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_key_share() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSKeyShareClientHelloView final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				UByte* data_;
				UInt size_;

			public:
				template<std::random_access_iterator Iter>
				TLSKeyShareClientHelloView(Iter first, Iter last)
				{
					data_ = first;
					auto length = get_tls_key_share_full_length();
					size_ = std::distance(first, first + length);
				}

				UShort get_tls_key_share_full_length() const;
				UShort get_tls_key_share_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_key_share() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSServerNameIndicationExtensionLittleEndian final {

			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:
				std::vector<UByte> data_;

			public:

				template <std::random_access_iterator Iter>
				TLSServerNameIndicationExtensionLittleEndian(Iter first, Iter last)
				{
					auto length_ = static_cast<UShort>(first[2] << 8 | first[3]);
					std::copy(first, first + length_ + 2, std::back_inserter(data_));
				}

				UShort get_tls_sni_full_length() const;
				UShort get_tls_sni_type() const;
				UShort get_tls_sni_length() const;
				UShort get_tls_sni_elem_length() const;
				TLSSNIRecordType get_tls_sni_record_type() const;
				UShort get_tls_sni_data_size() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_sni_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSServerNameIndicationExtensionView final {

			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt size_;

			public:

				template <std::random_access_iterator Iter>
				TLSServerNameIndicationExtensionView(Iter first, Iter last)
				{
					data_ = first;
					auto length = get_tls_sni_full_length(); // length + type (2 bytes)
					size_ = std::distance(first, first + length);
				}

				UShort get_tls_sni_full_length() const;
				UShort get_tls_sni_type() const;
				UShort get_tls_sni_length() const;
				UShort get_tls_sni_elem_length() const;
				TLSSNIRecordType get_tls_sni_record_type() const;
				UShort get_tls_sni_data_size() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_sni_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			template <class TLSRecordImpl>
			concept TLSRecordPacketLike =
				requires (TLSRecordImpl t) {
					{ t.get_tls_record_type() } -> std::same_as<TLSRecordType>;
					{ t.get_tls_record_version() } -> std::same_as<TLSProtocolVersion>;
					{ t.get_tls_record_length() } -> std::same_as<UShort>;
					{ t.get_tls_record_data() } -> std::same_as<std::pair<typename TLSRecordImpl::ConstDataIterator_t, typename TLSRecordImpl::ConstDataIterator_t>>;

			} && UnifiedPacketLike<TLSRecordImpl>;

			template <class TLSClientHelloImpl>
			concept TLS13_ClientHelloPacketLike =
				requires (TLSClientHelloImpl t) {
					{ t.get_tls_version() } -> std::same_as<UShort>;
					{ t.get_tls_random() } -> std::same_as<TLSRandomView>;
					{ t.get_tls_session() } -> std::same_as<TLSSessionIDView>;
					{ t.get_tls_cipher_suites() } -> std::same_as<TLSCipherSuitView>;
					{ t.get_tls_compression_methods() } -> std::same_as<TLSCompressionView>;
					{ t.get_tls_extensions_data() } -> std::same_as<TLSExtensionsView>;
					{ t.get_tls_sni_data() } -> std::same_as<TLSServerNameIndicationExtensionView>;

			} && UnifiedPacketLike<TLSClientHelloImpl>;


			template <class TLSServerHelloImpl>
			concept TLS13_ServerHelloPacketLike =
				requires (TLSServerHelloImpl t) {
					{ t.get_tls_version() } -> std::same_as<UShort>;
					{ t.get_tls_random() } -> std::same_as<TLSRandomView>;
					{ t.get_tls_session() } -> std::same_as<TLSSessionIDView>;
					{ t.get_tls_cipher_suites() } -> std::same_as<TLSCipherSuite>;
					{ t.get_tls_compression_methods() } -> std::same_as<TLSCompressionMethod>;
					{ t.get_tls_extensions_data() } -> std::same_as<TLSExtensionsView>;

			} && UnifiedPacketLike<TLSServerHelloImpl>;


			template <std::integral Val>
			struct TLS13_HelloPacketScheme
			{
				std::pair<Val, Val> random;
				std::pair<Val, Val> session;
				std::pair<Val, Val> ciphers;
				std::pair<Val, Val> compressions;
				std::pair<Val, Val> extensions;
			};


			class TLS13_ClientHelloPacketLittleEndian
			{

			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:
				std::vector<UByte> data_;
				TLS13_HelloPacketScheme<size_t> scheme_;

				void parse_scheme();

			public:

				TLS13_ClientHelloPacketLittleEndian(UByte* begin, UByte* end);

				UShort get_tls_version() const;
				TLSRandomView get_tls_random() const;
				TLSSessionIDView get_tls_session() const;
				TLSCipherSuitView get_tls_cipher_suites() const;
				TLSCompressionView get_tls_compression_methods() const;
				TLSExtensionsView get_tls_extensions_data() const;
				TLSServerNameIndicationExtensionView get_tls_sni_data() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLS13_ClientHelloPacketView
			{

			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt size_;
				TLS13_HelloPacketScheme<size_t> scheme_;

				void parse_scheme();

			public:

				TLS13_ClientHelloPacketView(UByte* begin, UByte* end);

				UShort get_tls_version() const;
				TLSRandomView get_tls_random() const;
				TLSSessionIDView get_tls_session() const;
				TLSCipherSuitView get_tls_cipher_suites() const;
				TLSCompressionView get_tls_compression_methods() const;
				TLSExtensionsView get_tls_extensions_data() const;
				TLSServerNameIndicationExtensionView get_tls_sni_data() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLS13_ServerHelloPacketLittleEndian
			{
			public:
				using DataIterator_t = std::vector<UByte>::iterator;
				using ConstDataIterator_t = std::vector<UByte>::const_iterator;

			private:
				std::vector<UByte> data_;
				TLS13_HelloPacketScheme<size_t> scheme_;

				void parse_scheme();

			public:

				TLS13_ServerHelloPacketLittleEndian(UByte* begin, UByte* end);

				UShort get_tls_version() const;
				TLSRandomView get_tls_random() const;
				TLSSessionIDView get_tls_session() const;
				TLSCipherSuite get_tls_cipher_suite() const;
				TLSCompressionMethod get_tls_compression_method() const;
				TLSExtensionsView get_tls_extensions_data() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				
			};


			class TLS13_ServerHelloPacketView
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt size_;
				TLS13_HelloPacketScheme<size_t> scheme_;

				void parse_scheme();

			public:

				TLS13_ServerHelloPacketView(UByte* begin, UByte* end);

				UShort get_tls_version() const;
				TLSRandomView get_tls_random() const;
				TLSSessionIDView get_tls_session() const;
				TLSCipherSuite get_tls_cipher_suite() const;
				TLSCompressionMethod get_tls_compression_method() const;
				TLSExtensionsView get_tls_extensions_data() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			template <class NetLayer>
			concept is_net_layer = Ip4PacketLike<NetLayer>;

			template <class TransportLayer>
			concept is_transport_layer = TcpPacketLike<TransportLayer> || UdpPacketLike<TransportLayer>;

			template <class DataLayer>
			concept is_data_layer = DataPacketLike<DataLayer> || HttpRequestPacketLike<DataLayer> || HttpResponsePacketLike<DataLayer>;


			template <class FullPacketImpl>
			concept FullPacketLike = is_net_layer<FullPacketImpl> && is_transport_layer<FullPacketImpl> && is_data_layer<FullPacketImpl>;

			template <is_net_layer NetLayer, is_transport_layer TransportLayer, is_data_layer DataLayer>
			class FullPacket : public NetLayer, public TransportLayer, public DataLayer
			{
			private:

			public:

				FullPacket(UByte* begin, UByte* end)
					: NetLayer(begin, end), TransportLayer(NetLayer::get_next_protocol_byte(), end), DataLayer(TransportLayer::get_next_protocol_byte(), end) {
				}

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
					: Ipv4Packet(begin, end), TcpPacket(Ipv4Packet::get_next_protocol_byte(), end), DataPacket(TcpPacket::get_next_protocol_byte(), end) {
				}

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
					: Ipv4Packet(begin, end), UdpPacket(Ipv4Packet::get_next_protocol_byte(), end), DataPacket(UdpPacket::get_next_protocol_byte(), end) {
				}

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
					: Ipv4Packet_View(begin, end), TcpPacket_View(Ipv4Packet_View::get_next_protocol_byte(), end), DataPacket_View(TcpPacket_View::get_next_protocol_byte(), end) {
				}

				std::pair<ConstDataIterator_t, ConstDataIterator_t> bytes()
				{
					auto [b1, e1] = Ipv4Packet_View::to_bytes();
					auto [b2, e2] = TcpPacket_View::to_bytes();
					auto [b3, e3] = DataPacket_View::to_bytes();
					return std::make_pair<>(b1, e3);
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
					: Ipv4Packet_View(begin, end), UdpPacketView(Ipv4Packet_View::get_next_protocol_byte(), end), DataPacket_View(UdpPacketView::get_next_protocol_byte(), end) {
				}

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

