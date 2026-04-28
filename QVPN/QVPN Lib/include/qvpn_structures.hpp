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
#include <concepts>
#include <ctime>
#include <utility>
#include <tuple>
#include <functional>
#include <algorithm>
#include <type_traits>
#include <stdexcept>
#include <random>
#include <sstream>




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


			enum TLSMessageType : UByte {
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

				// TLS 1.3
				// Основные рекомендуемые шифры
				TLS_AES_128_GCM_SHA256 = 0x1301,
				TLS_AES_256_GCM_SHA384 = 0x1302,
				TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
				TLS_AES_128_CCM_SHA256 = 0x1304,
				TLS_AES_128_CCM_8_SHA256 = 0x1305,

				// Резервные значения для будущих расширений
				RESERVED_1306 = 0x1306,
				RESERVED_1307 = 0x1307,


				// TLS 1.2
				// ====== ECDHE шифры (наиболее безопасные) ======

				// ECDHE + ECDSA
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,

				// ECDHE + RSA
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,

				// ====== DHE шифры (менее производительные) ======
				TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E,
				TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F,
				TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
				TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,

				// ====== RSA шифры (НЕБЕЗОПАСНЫ - без Forward Secrecy) ======
				TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,
				TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D,
				TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
				TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,

				// ====== УСТАРЕВШИЕ И НЕБЕЗОПАСНЫЕ ШИФРЫ ======
				TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A,
				TLS_RSA_WITH_RC4_128_MD5 = 0x0004,
				TLS_RSA_WITH_RC4_128_SHA = 0x0005,
				TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032,

				// ====== СЛУЖЕБНЫЕ И ТЕСТОВЫЕ ======
				TLS_NULL_WITH_NULL_NULL = 0x0000,
				TLS_RSA_WITH_NULL_MD5 = 0x0001,
				TLS_RSA_WITH_NULL_SHA = 0x0002
			};

			// Compression Method
			enum TLSCompressionMethod : UByte {
				NULL_COMPRESSION = 0x00
			};


			enum TLSKeyTypes : UShort {
				X25519 = 0x001D,
			};

			enum TLSKeyTypesLength : UShort
			{
				X25519_LENGTH = 32,
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


			template <class ProxyDataImpl>
			concept ProxyDataLike =
				requires (ProxyDataImpl t, const ProxyDataImpl & cr_proxy_data) {

					{ t.get_net_proto() } -> std::same_as<NetProtocol>;
					{ t.get_transport_proto() } -> std::same_as<TransportProtocol>;
					{ t.get_src_addr() } -> QVPN::Core::is_addr;
					{ t.get_src_port() } -> std::same_as<UShort>;
					{ t.get_dst_addr() } -> QVPN::Core::is_addr;
					{ t.get_dst_port() } -> std::same_as<UShort>;

					{ t.get_proto_data() } -> std::same_as<std::pair<UByte*, UByte*>>;
					{ t.get_proto_data_bytes() } -> std::same_as<std::pair<UByte*, UByte*>>;

					{ t.get_proxy_data_size() } -> std::same_as<UShort>;

					{ std::remove_const_t<std::remove_reference_t<ProxyDataImpl>>::create_and_inverse_addrs(cr_proxy_data) } -> std::same_as<std::remove_const_t<std::remove_reference_t<ProxyDataImpl>>>;
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

				template<class U, class AdapterHandler> requires is_adapter_criteria<U, AdapterHandler>
				std::shared_ptr<Adapter<AdapterHandler>> get_default_adapter()
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
				requires (PacketImpl t, const PacketImpl ct) {

				typename PacketImpl::DataIterator_t;
				typename PacketImpl::ConstDataIterator_t;

				//typename PacketImpl::ObjectType;
				//typename PacketImpl::ViewType;

				{ ct.to_bytes() } -> std::same_as<std::pair<typename PacketImpl::ConstDataIterator_t, typename PacketImpl::ConstDataIterator_t>>;
				{ t.to_bytes() } -> std::same_as<std::pair<typename PacketImpl::DataIterator_t, typename PacketImpl::DataIterator_t>>;

				//{ ct.to_object() } -> std::same_as<typename PacketImpl::ObjectType>;
				//{ ct.to_view() } -> std::same_as<typename PacketImpl::ViewType>;
			};

			template <class IpPacketImpl>
			concept UnifiedIpPacketLike =
				requires (IpPacketImpl t, const NetAddr & net_addr) {
					
					{ t.get_next_protocol_byte() } -> std::same_as<UByte*>;

					{ t.get_src_addr() } -> std::same_as<NetAddr>;
					{ t.get_dst_addr() } -> std::same_as<NetAddr>;

					{ t.set_src_addr(net_addr) } -> std::same_as<void>;
					{ t.set_dst_addr(net_addr) } -> std::same_as<void>;

					{ t.get_protocol_version() } -> std::same_as<NetProtocol>;
					{ t.get_transport_protocol() } -> std::same_as<TransportProtocol>;

					{ t.recalculate_ip_checksum() } -> std::same_as<void>;

					{ t.to_net_friendly_view() } -> std::same_as<std::string>;

			};

			template <class Ip4PacketImpl>
			concept Ip4PacketLike =
				requires (Ip4PacketImpl t) {

				typename Ip4PacketImpl::DataIterator_t;
				typename Ip4PacketImpl::ConstDataIterator_t;

				{ Ip4PacketImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
				
				{ t.parse_packet(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;
				{ t.get_ip_version() } -> std::same_as<NetProtocol>;
				{ t.get_ip_header_length() } -> std::same_as<UByte>;
				{ t.get_ip_dscp() } -> std::same_as<UByte>;
				{ t.get_ip_ecn() } -> std::same_as<UByte>;
				{ t.get_ip_total_length() } -> std::same_as<UShort>;
				{ t.get_ip_id() } -> std::same_as<UShort>;
				{ t.get_ip_flags() } -> std::same_as<UByte>;
				{ t.get_ip_offset() } -> std::same_as<UShort>;
				{ t.get_ip_ttl() } -> std::same_as<UByte>;
				{ t.get_ip_protocol() } -> std::same_as<TransportProtocol>;
				{ t.get_ip_checksum() } -> std::same_as<UShort>;
				{ t.get_ip_source() } -> std::same_as<IPv4Address>;
				{ t.get_ip_dest() } -> std::same_as<IPv4Address>;
				{ t.get_ip_additional_header() } -> std::same_as<std::pair<typename Ip4PacketImpl::ConstDataIterator_t, typename Ip4PacketImpl::ConstDataIterator_t>>;
				{ t.ip_to_friendly_view() } -> std::same_as<std::string>;


				{ t.set_ip_source(std::declval<const QVPN::Core::IPv4Address&>()) } -> std::same_as<void>;
				{ t.set_ip_dest(std::declval<const QVPN::Core::IPv4Address&>()) } -> std::same_as<void>;

				{ t.set_ip_checksum(std::declval<const UShort>()) } -> std::same_as<void>;

			}&& UnifiedIpPacketLike<Ip4PacketImpl>&& UnifiedPacketLike<Ip4PacketImpl>;


			template <class IPv4GenStrategyImpl>
			concept IPv4GenStrategyLike =
				requires (const IPv4GenStrategyImpl ct) {

					{ ct.get_ver() } -> std::same_as<NetProtocol>;
					{ ct.get_header_length() } -> std::same_as<UByte>;
					{ ct.get_dscp() } -> std::same_as<UByte>;
					{ ct.get_ecn() } -> std::same_as<UByte>;
					{ ct.get_qos() } -> std::same_as<UByte>;
					{ ct.get_id() } -> std::same_as<UShort>;
					{ ct.get_additional_headers() } -> std::same_as<std::vector<UByte>>;

			};


			class IPv4DefaultGenStrategy
			{
			private:
				mutable UShort last_id_ = 0;
			public:

				NetProtocol get_ver() const;
				UByte get_header_length() const;
				UByte get_dscp() const;
				UByte get_ecn() const;
				UByte get_qos() const;
				UShort get_id() const;
				std::vector<UByte> get_additional_headers() const;

				UShort get_next_id() const;

			};

			class Ipv4PacketView;

			class Ipv4PacketLittleEndian {

			private:

				std::vector<UByte> header_;
				UByte* next_protocol_;

			public:

				/* Unified Packet implementaion */
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				using ObjectType = Ipv4PacketLittleEndian;
				using ViewType = Ipv4PacketView;

				Ipv4PacketLittleEndian(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				NetProtocol get_ip_version() const;
				UByte get_ip_header_length() const;

				UByte get_ip_dscp() const;
				UByte get_ip_ecn() const;

				UShort get_ip_total_length() const;

				UShort get_ip_id() const;

				UByte  get_ip_flags() const;
				UShort get_ip_offset() const;

				UByte get_ip_ttl() const;
				TransportProtocol get_ip_protocol() const;

				UShort get_ip_checksum() const;

				IPv4Address get_ip_source() const;
				IPv4Address get_ip_dest() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_ip_additional_header() const;
				std::string ip_to_friendly_view() const;


				void set_ip_source(const QVPN::Core::IPv4Address& src);
				void set_ip_dest(const QVPN::Core::IPv4Address& dst);

				void set_ip_checksum(const UShort checksum);

				/* Unified Ip Packet implementaion */
				NetAddr get_src_addr() const;
				NetAddr get_dst_addr() const;

				NetProtocol get_protocol_version() const;
				TransportProtocol get_transport_protocol() const;

				void recalculate_ip_checksum();

				void set_src_addr(const NetAddr& net_addr);
				void set_dst_addr(const NetAddr& net_addr);

				// forward declaration из-за неполного viewtype
				template <IPv4GenStrategyLike IPv4GenStrategy>
				static inline std::vector<UByte> generate_object_bytes(const IPv4GenStrategy& strategy, const NetAddr& src, const NetAddr& dst, TransportProtocol proto, UShort total_length, bool DF, bool MF, UShort offset);

				template <IPv4GenStrategyLike IPv4GenStrategy>
				static ObjectType generate_object(const IPv4GenStrategy& strategy, const NetAddr& src, const NetAddr& dst, TransportProtocol proto, UShort total_length, bool DF, bool MF, UShort offset)
				{
					auto obj_bytes = generate_object_bytes<IPv4GenStrategy>(strategy, src, dst, proto, total_length, DF, MF, offset);
					return ObjectType(obj_bytes.data(), obj_bytes.data() + obj_bytes.size());
				}

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				ObjectType to_object() const;
				ViewType to_view() const;

				std::string to_net_friendly_view() const;

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

				using ObjectType = Ipv4PacketLittleEndian;
				using ViewType = Ipv4PacketView;

				Ipv4PacketView(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				NetProtocol get_ip_version() const;
				UByte get_ip_header_length() const;

				UByte get_ip_dscp() const;
				UByte get_ip_ecn() const;

				UShort get_ip_total_length() const;

				UShort get_ip_id() const;

				UByte  get_ip_flags() const;
				UShort get_ip_offset() const;

				UByte get_ip_ttl() const;
				TransportProtocol get_ip_protocol() const;

				UShort get_ip_checksum() const;

				IPv4Address get_ip_source() const;
				IPv4Address get_ip_dest() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_ip_additional_header() const;
				std::string ip_to_friendly_view() const;


				void set_ip_source(const QVPN::Core::IPv4Address& src);
				void set_ip_dest(const QVPN::Core::IPv4Address& dst);

				void set_ip_checksum(const UShort checksum);

				/* Unified Ip Packet implementaion */
				NetAddr get_src_addr() const;
				NetAddr get_dst_addr() const;

				NetProtocol get_protocol_version() const;
				TransportProtocol get_transport_protocol() const;

				void recalculate_ip_checksum();

				void set_src_addr(const NetAddr& net_addr);
				void set_dst_addr(const NetAddr& net_addr);


				template <IPv4GenStrategyLike IPv4GenStrategy>
				static std::vector<UByte> generate_object_bytes(const IPv4GenStrategy& strategy, const NetAddr& src, const NetAddr& dst, TransportProtocol proto, UShort total_length, bool DF, bool MF, UShort offset)
				{
					return ObjectType::generate_object_bytes(strategy, src, dst, proto, total_length, DF, MF, offset);
				}


				template <IPv4GenStrategyLike IPv4GenStrategy>
				static ObjectType generate_object(const IPv4GenStrategy& strategy, const NetAddr& src, const NetAddr& dst, TransportProtocol proto, UShort total_length, bool DF, bool MF, UShort offset)
				{
					return ObjectType::generate_object(strategy, src, dst, proto, total_length, DF, MF, offset);
				}


				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				ObjectType to_object() const;
				ViewType to_view() const;

				std::string to_net_friendly_view() const;

			};

			// Определение вне класса, иначе не работает ViewType, т.к. не полный Тип
			template<IPv4GenStrategyLike IPv4GenStrategy>
			inline std::vector<UByte> Ipv4PacketLittleEndian::generate_object_bytes(const IPv4GenStrategy& strategy, const NetAddr& src, const NetAddr& dst, TransportProtocol proto, UShort total_length, bool DF, bool MF, UShort offset)
			{
				std::vector<UByte> obj_bytes{};

				auto add_headers = strategy.get_additional_headers();
				auto size = add_headers.size() / 4;

				auto ver = strategy.get_ver();
				auto h_length = strategy.get_header_length();
				auto total_h_length = h_length + size;
				auto first_byte = static_cast<UByte>(ver << 4 | total_h_length & 0xF);
				obj_bytes.push_back(first_byte);

				auto qos = static_cast<UByte>(strategy.get_qos());
				obj_bytes.push_back(qos);

				auto len = total_length + total_h_length;

				obj_bytes.push_back(static_cast<UByte>(len >> 8));
				obj_bytes.push_back(static_cast<UByte>(len & 0xFF));

				UShort id = 0;
				if (MF)
					id = strategy.get_id();
				else
					id = strategy.get_next_id();

				obj_bytes.push_back(static_cast<UByte>(id >> 8));
				obj_bytes.push_back(static_cast<UByte>(id & 0xFF));

				UByte flags_offset = 0 << 7 | DF << 6 | MF << 5 | (offset >> 11) & 0b11111;
				obj_bytes.push_back(flags_offset);
				obj_bytes.push_back(static_cast<UByte>(offset & 0xFF));

				obj_bytes.push_back(static_cast<UByte>(proto));

				// checksum bytes
				obj_bytes.push_back(0);
				obj_bytes.push_back(0);

				auto src4 = src.to_ipv4();
				auto b_src = src4.to_bytes();
				std::copy(b_src.begin(), b_src.end(), std::back_inserter(obj_bytes));

				auto dst4 = dst.to_ipv4();
				auto b_dst = dst4.to_bytes();
				std::copy(b_dst.begin(), b_dst.end(), std::back_inserter(obj_bytes));

				std::copy(add_headers.begin(), add_headers.end(), std::back_inserter(obj_bytes));

				ViewType ip4(obj_bytes.data(), obj_bytes.data() + obj_bytes.size());
				ip4.recalculate_ip_checksum();

				return obj_bytes;

			}


			class DummyNetPacket
			{
			private:

			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = UByte*;

				DummyNetPacket() = default;

				template <std::random_access_iterator Iter>
				DummyNetPacket(Iter begin, Iter end)
				{

				}


				// NetLayer implementation
				/////////////////////

				UByte* get_next_protocol_byte() const;

				NetAddr get_src_addr() const;
				NetAddr get_dst_addr() const;

				void set_src_addr(const NetAddr& src);
				void set_dst_addr(const NetAddr& dst);

				NetProtocol get_protocol_version() const;
				TransportProtocol get_transport_protocol() const;

				void recalculate_ip_checksum();

				std::string to_net_friendly_view() const;
				/////////////////////


				// Unified Packet implementation
				////////////////////

				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				///////////////////

			};



			template <Ip4PacketLike Ip4PacketImpl>
			class Ipv4Packet_ : public Ip4PacketImpl {

			public:

				Ipv4Packet_(UByte* begin, UByte* end)
					: Ip4PacketImpl(begin, end) {}

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
				requires (TransportImpl t, UShort port, UShort length, UInt number, UByte flags) {

				typename TransportImpl::DataIterator_t;
				typename TransportImpl::ConstDataIterator_t;

				{ t.get_src_port() } -> std::same_as<UShort>;
				{ t.get_dst_port() } -> std::same_as<UShort>;
				{ t.get_transport_length() } -> std::same_as<UShort>;

				{ t.set_dst_port(port) } -> std::same_as<void>;

				{ t.set_transport_length(length) } -> std::same_as<void>;

				{ t.recalculate_transport_checksum(std::declval<const TransportIpv4PseudoHeader&>(), std::declval<typename TransportImpl::ConstDataIterator_t>(), std::declval<typename TransportImpl::ConstDataIterator_t>()) } -> std::same_as<void>;

				{ t.get_next_protocol_byte() } -> std::same_as<UByte*>;

				{ t.get_sender_number() } -> std::same_as<UInt>;
				{ t.get_receiver_number() } -> std::same_as<UInt>;
				{ t.get_flags() } -> std::same_as<UByte>;

				{ t.set_sender_number(number) } -> std::same_as<void>;
				{ t.set_receiver_number(number) } -> std::same_as<void>;
				{ t.set_flags(flags) } -> std::same_as<void>;

				{ t.to_transport_friendly_view() } -> std::same_as<std::string>;
			};

			template <class TcpImpl>
			concept TcpPacketLike =
				requires (TcpImpl t, UInt number, UByte flags, UShort ushort) {

					{ TcpImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
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

					{ t.set_tcp_seq_number(number) } -> std::same_as<void>;
					{ t.set_tcp_ack_number(number) } -> std::same_as<void>;
					{ t.set_tcp_flags(flags) } -> std::same_as<void>;
					{ t.set_tcp_offset(flags) } -> std::same_as<void>;
					{ t.set_tcp_window(ushort) } -> std::same_as<void>;
					{ t.set_tcp_urgent(ushort) } -> std::same_as<void>;

			}&& UnifiedTransportLike<TcpImpl>&& UnifiedPacketLike<TcpImpl>;


			enum TCPFlags : UByte
			{
				FIN = 0x01,
				SYN = 0x02,
				ACK = 0x10,
				SYN_ACK = 0x12,
			};


			class TcpPacketView;

			class TcpPacketLittleEndian
			{
			private:
				std::vector<UByte> header_;
				UByte* next_protocol_;

			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				using ObjectType = TcpPacketLittleEndian;
				using ViewType = TcpPacketView;

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

				UInt get_sender_number() const;
				UInt get_receiver_number() const;
				UByte get_flags() const;

				void set_sender_number(UInt number);
				void set_receiver_number(UInt number);
				void set_flags(UByte flags);

				void set_dst_port(UShort port);

				void set_transport_length(UShort length);
				void set_tcp_seq_number(UInt number);
				void set_tcp_ack_number(UInt number);
				void set_tcp_flags(UByte flags);
				void set_tcp_offset(UByte offset);
				void set_tcp_window(UShort window);
				void set_tcp_urgent(UShort urgent);

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				ObjectType to_object() const;
				ViewType to_view() const;

				std::string to_transport_friendly_view() const;

				// no checksum calcs
				static std::vector<UByte> generate_object_bytes(UShort src_port, UShort dst_port, UInt seq, UInt ack, UByte offset, UByte flags, UShort window_size, UShort urgent, UByte* opt_b, UByte* opt_e);
				static ObjectType generate_object(UShort src_port, UShort dst_port, UInt seq, UInt ack, UByte offset, UByte flags, UShort window_size, UShort urgent, UByte* opt_b, UByte* opt_e);

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

				using ObjectType = TcpPacketLittleEndian;
				using ViewType = TcpPacketView;

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

				UInt get_sender_number() const;
				UInt get_receiver_number() const;
				UByte get_flags() const;

				void set_sender_number(UInt number);
				void set_receiver_number(UInt number);
				void set_flags(UByte flags);
				void set_tcp_offset(UByte offset);
				void set_tcp_window(UShort window);
				void set_tcp_urgent(UShort urgent);

				void set_dst_port(UShort port);

				void set_transport_length(UShort length);
				void set_tcp_seq_number(UInt number);
				void set_tcp_ack_number(UInt number);
				void set_tcp_flags(UByte flags);

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				ObjectType to_object() const;
				ViewType to_view() const;

				std::string to_transport_friendly_view() const;

				// no checksum calcs
				static std::vector<UByte> generate_object_bytes(UShort src_port, UShort dst_port, UInt seq, UInt ack, UByte offset, UByte flags, UShort window_size, UShort urgent, UByte* opt_b, UByte* opt_e);
				static ObjectType generate_object(UShort src_port, UShort dst_port, UInt seq, UInt ack, UByte offset, UByte flags, UShort window_size, UShort urgent, UByte* opt_b, UByte* opt_e);

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
					{ t.parse_packet(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;
					{ t.get_udp_src_port() } -> std::same_as<UShort>;
					{ t.get_udp_dst_port() } -> std::same_as<UShort>;
					{ t.get_udp_length() } -> std::same_as<UShort>;
					{ t.get_udp_checksum() } -> std::same_as<UShort>;
					{ t.protocol_criteria(std::declval<UByte>()) } -> std::same_as<bool>;

			}&& UnifiedTransportLike<UdpImpl>&& UnifiedPacketLike<UdpImpl>;


			class UdpPacketView;

			class UdpPacketLittleEndian
			{
			private:
				std::vector<UByte> header_;
				UByte* next_protocol_;

			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				using ObjectType = UdpPacketLittleEndian;
				using ViewType = UdpPacketView;

				UdpPacketLittleEndian(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				UShort get_udp_src_port() const;
				UShort get_udp_dst_port() const;
				UShort get_udp_length() const;
				UShort get_udp_checksum() const;
				bool protocol_criteria(UByte protocol) const;


				void set_udp_checksum(UShort checksum);


				UShort get_src_port() const;
				UShort get_dst_port() const;
				void recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end);
				UShort get_transport_length() const;

				UInt get_sender_number() const;
				UInt get_receiver_number() const;
				UByte get_flags() const;

				std::string to_udp_friendly_view() const;

				void set_sender_number(UInt number);
				void set_receiver_number(UInt number);
				void set_flags(UByte flags);

				void set_dst_port(UShort port);

				void set_transport_length(UShort length);

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				ObjectType to_object() const;
				ViewType to_view() const;

				std::string to_transport_friendly_view() const;

				// no checksum calcs
				static std::vector<UByte> generate_object_bytes(UShort src_port, UShort dst_port, UShort length);
				static ObjectType generate_object(UShort src_port, UShort dst_port, UShort length);
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

				using ObjectType = UdpPacketLittleEndian;
				using ViewType = UdpPacketView;

				UdpPacketView(UByte* begin, UByte* end);

				void parse_packet(UByte* begin, UByte* end);

				UByte* get_next_protocol_byte();

				UShort get_udp_src_port() const;
				UShort get_udp_dst_port() const;
				UShort get_udp_length() const;
				UShort get_udp_checksum() const;
				bool protocol_criteria(UByte protocol) const;


				void set_udp_checksum(UShort checksum);

				UShort get_src_port() const;
				UShort get_dst_port() const;
				void recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end);
				UShort get_transport_length() const;

				UInt get_sender_number() const;
				UInt get_receiver_number() const;
				UByte get_flags() const;

				std::string to_udp_friendly_view() const;

				void set_sender_number(UInt number);
				void set_receiver_number(UInt number);
				void set_flags(UByte flags);

				void set_dst_port(UShort port);

				void set_transport_length(UShort length);

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				ObjectType to_object() const;
				ViewType to_view() const;

				std::string to_transport_friendly_view() const;

				// no checksum calcs
				static std::vector<UByte> generate_object_bytes(UShort src_port, UShort dst_port, UShort length);
				static ObjectType generate_object(UShort src_port, UShort dst_port, UShort length);
			};


			template <UdpPacketLike UdpImpl>
			class UdpPacket_ : public UdpImpl {

			public:

				UdpPacket_(UByte* begin, UByte* end)
					: UdpImpl(begin, end) {}


			};


			class DummyTransportPacket
			{
			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				DummyTransportPacket() = default;

				template <std::random_access_iterator Iter>
				DummyTransportPacket(Iter begin, Iter end)
				{

				}

				// TransportLayer implementation
				/////////////////////

				UShort get_src_port() const;
				UShort get_dst_port() const;
				UShort get_transport_length() const;

				void set_dst_port(UShort port);

				void set_transport_length(UShort length);

				void recalculate_transport_checksum(const TransportIpv4PseudoHeader& pseudo_header, ConstDataIterator_t begin, ConstDataIterator_t end);

				UByte* get_next_protocol_byte() const;

				UInt get_sender_number() const;
				UInt get_receiver_number() const;
				UByte get_flags() const;

				void set_sender_number(UInt number);
				void set_receiver_number(UInt number);
				void set_flags(UByte flags);

				std::string to_transport_friendly_view() const;

				/////////////////////


				// Unified Packet implementation
				////////////////////

				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				///////////////////

			};


			template <class TransportAndDataImpl>
			concept TransportAndDataPacketLike =
				requires (TransportAndDataImpl t) {

				typename TransportAndDataImpl::DataIterator_t;
				typename TransportAndDataImpl::ConstDataIterator_t;

				{ TransportAndDataImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
				{ t.parse_packet(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;
				{ t.get_custom_data() } -> std::same_as<std::pair<typename TransportAndDataImpl::ConstDataIterator_t, typename TransportAndDataImpl::ConstDataIterator_t>>;
				{ t.protocol_criteria(std::declval<UByte>()) } -> std::same_as<bool>;

			}&& UnifiedTransportLike<TransportAndDataImpl>&& UnifiedPacketLike<TransportAndDataImpl>;



			template <class DataPacketImpl>
			concept DataPacketLike = requires (DataPacketImpl t, const DataPacketImpl ct) {

				typename DataPacketImpl::DataIterator_t;
				typename DataPacketImpl::ConstDataIterator_t;

				{ DataPacketImpl(std::declval<UByte*>(), std::declval<UByte*>()) };
				{ t.get_data() } -> std::same_as<std::pair<typename DataPacketImpl::DataIterator_t, typename DataPacketImpl::DataIterator_t>>;
				{ ct.get_data() } -> std::same_as<std::pair<typename DataPacketImpl::ConstDataIterator_t, typename DataPacketImpl::ConstDataIterator_t>>;
				{ t.set_data(std::declval<UByte*>(), std::declval<UByte*>()) } -> std::same_as<void>;
				{ ct.to_data_friendly_view() } -> std::same_as<std::string>;

			}&& UnifiedPacketLike<DataPacketImpl>;


			class DataPacketView;

			class DataPacketLittleEndian
			{
			private:
				std::vector<UByte> data_;

			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				using ObjectType = DataPacketLittleEndian;
				using ViewType = DataPacketView;

				DataPacketLittleEndian(UByte* begin, UByte* end);
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_data() const;
				std::pair<DataIterator_t, DataIterator_t> get_data();

				void set_data(UByte* begin, UByte* end);

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				ObjectType to_object() const;
				ViewType to_view() const;

				std::string to_data_friendly_view() const;
			};



			class DataPacketView
			{
			private:
				UByte* data_;

				int data_size_ = 0;

			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				using ObjectType = DataPacketLittleEndian;
				using ViewType = DataPacketView;

				DataPacketView(UByte* begin, UByte* end);
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_data() const;
				std::pair<DataIterator_t, DataIterator_t> get_data();

				void set_data(UByte* begin, UByte* end);

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				ObjectType to_object() const;
				ViewType to_view() const;

				std::string to_data_friendly_view() const;
			};



			class DummyDataPacket
			{
			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;


				DummyDataPacket() = default;

				template <std::random_access_iterator Iter>
				DummyDataPacket(Iter begin, Iter end)
				{

				}

				// DataLayer implementation
				/////////////////////

				std::pair<DataIterator_t, DataIterator_t> get_data();
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_data() const;
				void set_data(UByte* begin, UByte* end);
				std::string to_data_friendly_view() const;

				/////////////////////


				// Unified Packet implementation
				////////////////////

				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
				std::pair<DataIterator_t, DataIterator_t> to_bytes();

				///////////////////

			};


			template <DataPacketLike DataPacketImpl>
			class DataPacket_ : public DataPacketImpl
			{
			public:
				DataPacket_(UByte* begin, UByte* end)
					: DataPacketImpl(begin, end) {}
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
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

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
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

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
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				std::array<UByte, 32> random_bytes_;

			public:

				template<std::random_access_iterator Iter>
				TLSRandomLittleEndian(Iter first, Iter last)
				{
					std::copy(first, first + 32, random_bytes_.begin());
				}

				// generator for qvpn protcol (for net protocol + transport protocol + dest ip)
				//example: ipv4 (1 byte) + tcp (1 byte) + ip_addr (4 bytes)
				// no need
				template <std::random_access_iterator Iter>
				static std::array<UByte, 32> generate_object_bytes(Iter begin, Iter end)
				{
					std::array<UByte, 32> obj_bytes;

					std::random_device rd;
					std::mt19937 gen(rd());
					std::uniform_int_distribution<UInt> dist(0, 255);

					int time = std::time(nullptr);
					obj_bytes.at(0) = (time >> 24 & 0xFF);
					obj_bytes.at(1) = (time >> 16 & 0xFF);
					obj_bytes.at(2) = (time >> 8 & 0xFF);
					obj_bytes.at(3) = (time & 0xFF);

					auto size = std::distance(begin, end);
					if (size > 28)
					{
						throw std::out_of_range("size must be 28 or less");
					}

					std::copy(begin + 4, end, std::back_inserter(obj_bytes));

					if (size < 28)
						std::generate(obj_bytes.begin() + size + 4, obj_bytes.end(), [&dist, &gen]() { return dist(gen); });

					return obj_bytes;
				}

				template <std::random_access_iterator Iter>
				static TLSRandomLittleEndian generate_object(Iter begin, Iter end)
				{
					auto obj_bytes = TLSRandomLittleEndian::generate_object_bytes<Iter>(begin, end);
					return TLSRandomLittleEndian(begin, end);
				}

				static std::array<UByte, 32> generate_object_bytes();
				static TLSRandomLittleEndian generate_object();


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

				// generator for qvpn protcol (for net protocol + transport protocol + dest ip)
				//example: ipv4 (1 byte) + tcp (1 byte) + ip_addr (4 bytes)
				template <std::random_access_iterator Iter>
				static std::array<UByte, 32> generate_object_bytes(Iter begin, Iter end)
				{
					return TLSRandomLittleEndian::generate_object_bytes<Iter>(begin, end);
				}

				template <std::random_access_iterator Iter>
				static TLSRandomLittleEndian generate_object(Iter begin, Iter end)
				{
					return TLSRandomLittleEndian::generate_object<Iter>(begin, end);
				}

				static std::array<UByte, 32> generate_object_bytes();
				static TLSRandomLittleEndian generate_object();


				UShort get_tls_random_full_length() const;
				UInt get_tls_unix_time() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_random_bytes() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			// Session ID
			class TLSSessionIDLittleEndian final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				std::vector<UByte> id_;

			public:

				template<std::random_access_iterator Iter>
				TLSSessionIDLittleEndian(Iter first, Iter last)
				{
					auto length = first[0];
					std::copy(first, first + length + 1, std::back_inserter(id_));
				}

				// generator for qvpn protcol (for cipher key)
				template <std::random_access_iterator Iter1, std::random_access_iterator Iter2>
					requires std::is_same_v<Iter1, Iter2>
				static std::vector<UByte> generate_object_bytes(Iter1 begin, Iter2 end)
				{
					UByte size = std::distance(begin, end);
					std::vector<UByte> obj_bytes;
					obj_bytes.push_back(size);
					std::copy(begin, end, std::back_inserter(obj_bytes));
					return obj_bytes;
				}

				template <std::random_access_iterator Iter1, std::random_access_iterator Iter2>
					requires std::is_same_v<Iter1, Iter2>
				static TLSSessionIDLittleEndian generate_object(Iter1 begin, Iter2 end)
				{
					auto obj_bytes = generate_object_bytes<Iter1, Iter2>(begin, end);
					return TLSSessionIDLittleEndian(obj_bytes.data(), obj_bytes.end());
				}

				static std::vector<UByte> generate_object_bytes(UByte length = 32);
				static TLSSessionIDLittleEndian generate_object(UByte length = 32);

				UShort get_tls_id_full_length() const;
				UByte get_tls_id_length() const;
				std::pair<DataIterator_t, DataIterator_t> get_tls_id();
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_id() const;

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

				// generator for qvpn protcol (for cipher key)
				template <std::random_access_iterator Iter1, std::random_access_iterator Iter2>
				static std::vector<UByte> generate_object_bytes(Iter1 begin, Iter2 end)
				{
					return TLSSessionIDLittleEndian::generate_object_bytes<Iter1, Iter2>(begin, end);
				}

				template <std::random_access_iterator Iter1, std::random_access_iterator Iter2>
				static std::vector<UByte> generate_object(Iter1 begin, Iter2 end)
				{
					return TLSSessionIDLittleEndian::generate_object<Iter1, Iter2>(begin, end);
				}


				static std::vector<UByte> generate_object_bytes(UByte length = 32);
				static TLSSessionIDLittleEndian generate_object(UByte length = 32);


				UInt get_tls_id_full_length() const;
				UByte get_tls_id_length() const;
				std::pair<DataIterator_t, DataIterator_t> get_tls_id();
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_id() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSCipherSuitLittleEndian final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				std::vector<UByte> ciphers_;

			public:

				template<std::random_access_iterator Iter>
				TLSCipherSuitLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[0] << 8 | first[1]);
					std::copy(first, first + length + 2, std::back_inserter(ciphers_));
				}


				static std::vector<UByte> generate_object_bytes(UShort length = 34);
				static TLSCipherSuitLittleEndian generate_object(UShort length = 34);


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


				static std::vector<UByte> generate_object_bytes(UShort length = 34);
				static TLSCipherSuitLittleEndian generate_object(UShort length = 34);


				UShort get_tls_ciphers_full_length() const;
				UShort get_tls_ciphers_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_cipher_suites() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSCompressionLittleEndian final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				std::vector<UByte> compressions_;

			public:
				template<std::random_access_iterator Iter>
				TLSCompressionLittleEndian(Iter first, Iter last)
				{
					auto length = first[0];
					std::copy(first, first + length + 1, std::back_inserter(compressions_));
				}

				static std::vector<UByte> generate_object_bytes(UByte length = 1);
				static TLSCompressionLittleEndian generate_object(UByte length = 1);

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


				static std::vector<UByte> generate_object_bytes(UByte length = 1);
				static TLSCompressionLittleEndian generate_object(UByte length = 1);


				UShort get_tls_compressions_full_length() const;
				UByte get_tls_compressions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_compressions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			template <class TLSExtensionImpl, class ... Args>
			concept TLSExtensionGenerator =
				requires (TLSExtensionImpl t, Args ... args) {

					{ TLSExtensionImpl::generate_object_bytes(args...) } -> std::same_as<std::vector<UByte>>;
					{ TLSExtensionImpl::generate_object(args...) } -> std::same_as<TLSExtensionImpl>;
					{ TLSExtensionImpl::get_extension_type() } -> std::same_as<TLSExtensionType>;

			}&& UnifiedPacketLike<TLSExtensionImpl>;


			template <class TLSExtensionImpl, class ... Args>
			concept TLSExtensionWrapperGenerator =
				requires (TLSExtensionImpl t) {

				typename TLSExtensionImpl::ArgsType;
				{ t.get_args() } -> std::same_as<std::tuple<Args...>&>;

			}&& TLSExtensionGenerator<TLSExtensionImpl, Args...>;


			// Структура для расширений
			class TLSExtensionLittleEndian {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				std::vector<UByte> data_;

			public:

				template<std::random_access_iterator Iter>
				TLSExtensionLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[2] << 8 | first[3]);
					std::copy(first, first + length + 4, std::back_inserter(data_));
				}

				template <class TLSExtension>
				static TLSExtensionType get_extension_type()
				{
					return TLSExtension::get_extension_type();
				}

				template <class TLSExtension, class ... FuncArgs>
				static std::vector<UByte> generate_object_bytes(FuncArgs&& ... args)
				{
					std::vector<UByte> obj_bytes;
					auto ext_bytes = TLSExtension::generate_object_bytes(std::forward<FuncArgs>(args)...);
					auto ext_type = static_cast<UShort>(TLSExtension::get_extension_type());
					auto length = ext_bytes.size();
					obj_bytes.push_back(ext_type >> 8 & 0xFF);
					obj_bytes.push_back(ext_type & 0xFF);
					obj_bytes.push_back(static_cast<UByte>(length >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(length & 0xFF));
					std::copy(ext_bytes.begin(), ext_bytes.end(), std::back_inserter(obj_bytes));
					return obj_bytes;
				}

				template <class TLSExtension, class ... Args>
				static TLSExtensionLittleEndian generate_object(Args&& ... args)
				{
					auto obj_bytes = generate_object_bytes<TLSExtension, Args...>(args...);
					return TLSExtensionLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}

				UShort get_tls_ext_full_length() const;
				TLSExtensionType get_tls_ext_type() const;
				UShort get_tls_ext_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_ext_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSExtensionView {
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


				template <class TLSExtension>
				static TLSExtensionType get_extension_type()
				{
					return TLSExtension::get_extension_type();
				}

				template <class TLSExtension, class ... FuncArgs>
				static std::vector<UByte> generate_object_bytes(FuncArgs&& ... args)
				{
					return TLSExtensionLittleEndian::generate_object_bytes<TLSExtension, FuncArgs...>(std::forward<FuncArgs>(args)...);
				}

				template <class TLSExtension, class ... FuncArgs>
				static TLSExtensionLittleEndian generate_object(FuncArgs&& ... args)
				{
					return TLSExtensionLittleEndian::generate_object<TLSExtension, FuncArgs...>(std::forward<FuncArgs>(args)...);
				}


				UShort get_tls_ext_full_length() const;
				TLSExtensionType get_tls_ext_type() const;
				UShort get_tls_ext_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_ext_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;

			};

			// разобраться с концептами (TLSExtensionWrapperGenerator, ...)
			template <class TLSExtension, class TLSExtensionData, class ... Args>
			class TLSExtensionWrapper final
			{
			private:

				std::tuple<Args...> args_;

			public:

				template<class ... FuncArgs>
				TLSExtensionWrapper(FuncArgs&& ... args)
					: args_(std::forward<FuncArgs>(args)...) {}

				std::tuple<Args...>& get_args()
				{
					return args_;
				}

				static TLSExtensionType get_extension_type()
				{
					return TLSExtension::get_extension_type();
				}

				template <class ... FuncArgs>
				static std::vector<UByte> generate_object_bytes(FuncArgs&&... args)
				{
					return TLSExtension:: template generate_object_bytes<TLSExtensionData, FuncArgs...>(std::forward<FuncArgs>(args)...);
				}

				template <class ... FuncArgs>
				static TLSExtension generate_object(FuncArgs&& ... args)
				{
					return TLSExtension:: template generate_object<TLSExtensionData, FuncArgs...>(std::forward<FuncArgs>(args)...);
				}
			};

			class TLSExtensionsLittleEndian final
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				std::vector<UByte> extensions_;

				// wrapper to unpack tuple params
				template <class ExtWrapper, class Tuple>
				static decltype(auto) extension_wrapper_caller(Tuple&& tuple)
				{
					using NoRefTupleType = std::remove_reference_t<Tuple>;
					return[&]<size_t ... args_index>(std::index_sequence<args_index ...>)
					{
						return std::apply(ExtWrapper:: template generate_object_bytes<std::tuple_element_t<args_index, NoRefTupleType>...>, std::forward<NoRefTupleType>(tuple));
					}(std::make_index_sequence<std::tuple_size_v<NoRefTupleType>>{});
				}

			public:

				template<std::random_access_iterator Iter>
				TLSExtensionsLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[0] << 8 | first[1]);
					std::copy(first, first + length + 2, std::back_inserter(extensions_));
				}


				template <class ... TLSExtensionWrapperType> // разобраться с концпетом TLSExtensionWrapperGenerator
				static std::vector<UByte> generate_object_bytes(TLSExtensionWrapperType&& ... ext)
				{
					std::vector<std::vector<UByte>> obj_bytes{};
					std::vector<UByte> res{};
					UShort size = 0;

					((obj_bytes.push_back(extension_wrapper_caller<TLSExtensionWrapperType>(ext.get_args()))), ...);
					[&] <size_t... i> (std::index_sequence<i...>) {
						((size += obj_bytes[i].size()), ...);
						((std::copy(obj_bytes[i].begin(), obj_bytes[i].end(), std::back_inserter(res))), ...);
					}(std::make_index_sequence<sizeof...(TLSExtensionWrapperType)>{});

					res.insert(res.begin(), static_cast<UByte>(size >> 8 & 0xFF));
					res.insert(res.begin() + 1, static_cast<UByte>(size & 0xFF));
					return res;
				}

				template<class ...TLSExtensionWrapperType> // разобраться с концпетом TLSExtensionWrapperGenerator
				static TLSExtensionsLittleEndian generate_object(TLSExtensionWrapperType&& ... ext)
				{
					auto objs_bytes = generate_object_bytes<TLSExtensionWrapperType...>(std::forward<TLSExtensionWrapperType>(ext)...);
					return TLSExtensionsLittleEndian(objs_bytes.begin(), objs_bytes.end());
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


				template <class ... TLSExtensionWrapperType> // разобраться с концпетом TLSExtensionWrapperGenerator
				static std::vector<UByte> generate_object_bytes(TLSExtensionWrapperType&& ... ext)
				{
					return TLSExtensionsLittleEndian::generate_object_bytes<TLSExtensionWrapperType...>(std::forward<TLSExtensionWrapperType>(ext)...);
				}

				template<class ...TLSExtensionWrapperType> // разобраться с концпетом TLSExtensionWrapperGenerator
				static TLSExtensionsLittleEndian generate_object(TLSExtensionWrapperType&& ... ext)
				{
					return TLSExtensionsLittleEndian::generate_object<TLSExtensionWrapperType...>(std::forward<TLSExtensionWrapperType>(ext)...);
				}


				UShort get_tls_extensions_full_length() const;
				UShort get_tls_extensions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_extensions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			using SupVerIter = std::vector<TLSProtocolVersion>::iterator;
			using KeyShareIter = std::vector<std::pair<TLSKeyTypes, TLSKeyTypesLength>>::iterator;
			using SNIIter = std::vector<std::string_view>::iterator;

			class TLSSupportedVersionsEntryLittleEndian final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				std::vector<UByte> data_;

			public:
				template<std::random_access_iterator Iter>
				TLSSupportedVersionsEntryLittleEndian(Iter first, Iter last)
				{
					std::copy(first, first + 2, std::back_inserter(data_));
				}


				static std::vector<UByte> generate_object_bytes(UShort length = 2, TLSProtocolVersion version = TLSProtocolVersion::TLS13);
				static TLSSupportedVersionsEntryLittleEndian generate_object(UShort length = 2, TLSProtocolVersion version = TLSProtocolVersion::TLS13);


				UShort get_tls_versions_full_length() const;
				UShort get_tls_versions_length() const;
				TLSProtocolVersion get_tls_supported_version_value() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_supported_version() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSSupportedVersionsEntryView final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				UByte* data_;
				UInt size_;

			public:
				template<std::random_access_iterator Iter>
				TLSSupportedVersionsEntryView(Iter first, Iter last)
				{
					data_ = first;
					size_ = 2;
				}


				static std::vector<UByte> generate_object_bytes(UShort length = 2, TLSProtocolVersion version = TLSProtocolVersion::TLS13);
				static TLSSupportedVersionsEntryLittleEndian generate_object(UShort length = 2, TLSProtocolVersion version = TLSProtocolVersion::TLS13);


				UShort get_tls_versions_full_length() const;
				UShort get_tls_versions_length() const;
				TLSProtocolVersion get_tls_supported_version_value() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_supported_version() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			// Client hello Supported Versions Extension
			class TLSSupportedVersionsClientHelloExtensionLittleEndian {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				std::vector<UByte> versions_;

			protected:
				TLSSupportedVersionsClientHelloExtensionLittleEndian() = default;

			public:
				template<std::random_access_iterator Iter>
				TLSSupportedVersionsClientHelloExtensionLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UByte>(first[0]);
					std::copy(first, first + length + 1, std::back_inserter(versions_));
				}


				static TLSExtensionType get_extension_type();
				static std::vector<UByte> generate_object_bytes(std::pair<SupVerIter, SupVerIter> versions);
				static TLSSupportedVersionsClientHelloExtensionLittleEndian generate_object(std::pair<SupVerIter, SupVerIter> versions);

				UShort get_tls_versions_full_length() const;
				UByte get_tls_versions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_supported_versions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSSupportedVersionsClientHelloExtensionView {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				UByte* data_;
				UInt size_;

			public:
				template<std::random_access_iterator Iter>
				TLSSupportedVersionsClientHelloExtensionView(Iter first, Iter last)
				{
					data_ = first;
					auto length = get_tls_versions_full_length();
					size_ = std::distance(first, first + length);
				}


				static TLSExtensionType get_extension_type();
				static std::vector<UByte> generate_object_bytes(std::pair<SupVerIter, SupVerIter> versions);
				static TLSSupportedVersionsClientHelloExtensionLittleEndian generate_object(std::pair<SupVerIter, SupVerIter> versions);


				UShort get_tls_versions_full_length() const;
				UByte get_tls_versions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_supported_versions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			// Server hello Supported Versions Extension
			class TLSSupportedVersionsServerHelloExtensionLittleEndian {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				std::vector<UByte> versions_;

			protected:
				TLSSupportedVersionsServerHelloExtensionLittleEndian() = default;

			public:
				template<std::random_access_iterator Iter>
				TLSSupportedVersionsServerHelloExtensionLittleEndian(Iter first, Iter last)
				{
					auto length = 2;
					std::copy(first, first + 2, std::back_inserter(versions_));
				}


				static TLSExtensionType get_extension_type();
				static std::vector<UByte> generate_object_bytes(TLSProtocolVersion version);
				static TLSSupportedVersionsServerHelloExtensionLittleEndian generate_object(TLSProtocolVersion version);

				UShort get_tls_versions_full_length() const;
				UShort get_tls_versions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_supported_version() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSSupportedVersionsServerHelloExtensionView {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				UByte* data_;
				UInt size_;

			public:
				template<std::random_access_iterator Iter>
				TLSSupportedVersionsServerHelloExtensionView(Iter first, Iter last)
				{
					data_ = first;
					auto length = get_tls_versions_full_length();
					size_ = std::distance(first, first + length);
				}


				static TLSExtensionType get_extension_type();
				static std::vector<UByte> generate_object_bytes(TLSProtocolVersion version);
				static TLSSupportedVersionsServerHelloExtensionLittleEndian generate_object(TLSProtocolVersion version);


				UShort get_tls_versions_full_length() const;
				UShort get_tls_versions_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_supported_versions() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			// Key Share Entry
			class TLSKeyShareEntryLittleEndian final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				std::vector<UByte> key_exchange_;

			public:

				template<std::random_access_iterator Iter>
				TLSKeyShareEntryLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[2] << 8 | first[3]);
					std::copy(first, first + length + 4, std::back_inserter(key_exchange_));
				}

				static std::vector<UByte> generate_object_bytes(UShort length = 32, TLSKeyTypes key_type = TLSKeyTypes::X25519);
				static TLSKeyShareEntryLittleEndian generate_object(UShort length = 32, TLSKeyTypes key_type = TLSKeyTypes::X25519);

				UShort get_tls_key_share_entry_full_length() const;
				UShort get_tls_key_share_entry_length() const;
				UShort get_tls_key_share_key_type() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_key_data() const;

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
					auto length = get_tls_key_share_entry_full_length();
					size_ = std::distance(first, first + length);
				}


				static std::vector<UByte> generate_object_bytes(UShort length = 32, TLSKeyTypes key_type = TLSKeyTypes::X25519);
				static TLSKeyShareEntryLittleEndian generate_object(UShort length = 32, TLSKeyTypes key_type = TLSKeyTypes::X25519);


				UShort get_tls_key_share_entry_full_length() const;
				UShort get_tls_key_share_key_type() const;
				UShort get_tls_key_share_entry_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_key_exchange() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			// Key Share Extension
			class TLSKeyShareClientHelloLittleEndian {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				std::vector<UByte> client_shares_;

			public:
				template<std::random_access_iterator Iter>
				TLSKeyShareClientHelloLittleEndian(Iter first, Iter last)
				{
					auto length = static_cast<UShort>(first[0] << 8 | first[1]);
					std::copy(first, first + length + 2, std::back_inserter(client_shares_));
				}

				static TLSExtensionType get_extension_type();
				static std::vector<UByte> generate_object_bytes(std::pair<KeyShareIter, KeyShareIter> key_shares);
				static TLSKeyShareEntryLittleEndian generate_object(std::pair<KeyShareIter, KeyShareIter> key_shares);

				UShort get_tls_key_share_full_length() const;
				UShort get_tls_key_share_length() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_key_share() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSKeyShareClientHelloView {
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


				static TLSExtensionType get_extension_type();
				static std::vector<UByte> generate_object_bytes(std::pair<KeyShareIter, KeyShareIter> key_shares);
				static TLSKeyShareEntryLittleEndian generate_object(std::pair<KeyShareIter, KeyShareIter> key_shares);


				UShort get_tls_key_share_full_length() const;
				UShort get_tls_key_share_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_key_share() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSServerNameIndicationEntryLittleEndian final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				std::vector<UByte> data_;

			public:

				template <std::random_access_iterator Iter>
				TLSServerNameIndicationEntryLittleEndian(Iter first, Iter last)
				{
					auto length_ = static_cast<UShort>(first[1] << 8 | first[2]);
					std::copy(first, first + length_ + 3, std::back_inserter(data_));
				}

				static std::vector<UByte> generate_object_bytes(UShort length = 6, std::string_view host = "vk.com");
				static TLSServerNameIndicationEntryLittleEndian generate_object(UShort length = 6, std::string_view host = "vk.com");

				UShort get_tls_sni_full_length() const;
				UShort get_tls_sni_length() const;
				TLSSNIRecordType get_tls_sni_record_type() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_sni_entry_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSServerNameIndicationEntryView final {
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				UByte* data_;
				UInt size_;

			public:

				template <std::random_access_iterator Iter>
				TLSServerNameIndicationEntryView(Iter first, Iter last)
				{
					data_ = first;
					auto length_ = static_cast<UShort>(first[1] << 8 | first[2]);
					size_ = length_ + 3;
				}

				static std::vector<UByte> generate_object_bytes(UShort length = 6, std::string_view host = "vk.com");
				static TLSServerNameIndicationEntryLittleEndian generate_object(UShort length = 6, std::string_view host = "vk.com");

				UShort get_tls_sni_full_length() const;
				UShort get_tls_sni_length() const;
				TLSSNIRecordType get_tls_sni_record_type() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_sni_entry_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			class TLSServerNameIndicationExtensionLittleEndian {

			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:
				std::vector<UByte> data_;

			public:

				template <std::random_access_iterator Iter>
				TLSServerNameIndicationExtensionLittleEndian(Iter first, Iter last)
				{
					auto length_ = static_cast<UShort>(first[0] << 8 | first[1]);
					std::copy(first, first + length_ + 2, std::back_inserter(data_));
				}

				static TLSExtensionType get_extension_type();
				static std::vector<UByte> generate_object_bytes(std::pair<SNIIter, SNIIter> hosts);
				static TLSServerNameIndicationExtensionLittleEndian generate_object(std::pair<SNIIter, SNIIter> hosts);

				UShort get_tls_sni_full_length() const;
				UShort get_tls_sni_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_sni_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLSServerNameIndicationExtensionView {

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

				static TLSExtensionType get_extension_type();
				static std::vector<UByte> generate_object_bytes(std::pair<SNIIter, SNIIter> hosts);
				static TLSServerNameIndicationExtensionLittleEndian generate_object(std::pair<SNIIter, SNIIter> hosts);

				UShort get_tls_sni_full_length() const;
				UShort get_tls_sni_length() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_sni_data() const;

				/* Unified Packet implementaion */
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			template <class TLSRecordImpl>
			concept TLSRecordPacketLike =
				requires (TLSRecordImpl t) {
					{ t.get_tls_record_type() } -> std::same_as<TLSRecordType>;
					{ t.get_tls_protocol_version() } -> std::same_as<TLSProtocolVersion>;
					{ t.get_tls_record_full_length() } -> std::same_as<UShort>;
					{ t.get_tls_record_length() } -> std::same_as<UShort>;
					{ t.get_tls_record_data() } -> std::same_as<std::pair<typename TLSRecordImpl::ConstDataIterator_t, typename TLSRecordImpl::ConstDataIterator_t>>;

			}&& UnifiedPacketLike<TLSRecordImpl>;


			template <class TLSMessageImpl>
			concept TLS13_MessagePacketLike =
				requires (TLSMessageImpl t) {
					{ t.get_tls_msg_type() } -> std::same_as<TLSMessageType>;
					{ t.get_tls_msg_length() } -> std::same_as<UInt>;
					{ t.get_tls_msg_full_length() } -> std::same_as<UInt>;
					{ t.get_tls_msg_data() } -> std::same_as<std::pair<typename TLSMessageImpl::ConstDataIterator_t, typename TLSMessageImpl::ConstDataIterator_t>>;

			}&& UnifiedPacketLike<TLSMessageImpl>;


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

			}&& UnifiedPacketLike<TLSClientHelloImpl>;


			template <class TLSServerHelloImpl>
			concept TLS13_ServerHelloPacketLike =
				requires (TLSServerHelloImpl t) {

					{ t.get_tls_version() } -> std::same_as<UShort>;
					{ t.get_tls_random() } -> std::same_as<TLSRandomView>;
					{ t.get_tls_session() } -> std::same_as<TLSSessionIDView>;
					{ t.get_tls_cipher_suites() } -> std::same_as<TLSCipherSuite>;
					{ t.get_tls_compression_methods() } -> std::same_as<TLSCompressionMethod>;
					{ t.get_tls_extensions_data() } -> std::same_as<TLSExtensionsView>;

			}&& UnifiedPacketLike<TLSServerHelloImpl>;


			template <class TLSPacketImpl, class ... Args> // not TLSExtensionGenerator
			concept TLSPacketGeneratorLike =
				requires (TLSPacketImpl t, Args&& ... args) {

				typename TLSPacketImpl::OverlayProtocolType;
				{ TLSPacketImpl::get_overlay_protocol_type() } -> std::same_as<typename TLSPacketImpl::OverlayProtocolType>;
				{ TLSPacketImpl::generate_object_bytes(args...) } -> std::same_as<std::vector<UByte>>;
				{ TLSPacketImpl::generate_object(args...) } -> std::same_as<TLSPacketImpl>;

			};


			template <class TLSPacketImpl, class ... Args>
			concept TLSHelloPacketGeneratorLike = TLSPacketGeneratorLike<TLSPacketImpl, Args...> && (TLS13_ClientHelloPacketLike<TLSPacketImpl> || TLS13_ServerHelloPacketLike<TLSPacketImpl>);


			template <class TLSStrategy>
			concept TLSRecordGenerationStrategy =
				requires (TLSStrategy t) {

					{ t.get_legacy_version() } -> std::same_as<TLSProtocolVersion>;
			};


			class TLS13_DefaultRecordGenerationStrategy
			{
			public:

				TLSProtocolVersion get_legacy_version() const;
			};

			class TLS13_RecordLittleEndian
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				std::vector<UByte> data_;

			public:

				template <std::random_access_iterator Iter>
				TLS13_RecordLittleEndian(Iter begin, Iter end)
				{
					std::copy(begin, end, std::back_inserter(data_));
				}

				// generator for handshake messages
				template <TLSRecordGenerationStrategy TLSRecordGenStrategy, class TLSPacketGenerator, class TLSUnderlayingPacketGenerator, class ... Args>
					requires TLSPacketGeneratorLike<TLSUnderlayingPacketGenerator, Args...> //&& TLSPacketGeneratorLike<TLSPacketGenerator, Args...>
				static std::vector<UByte> generate_object_bytes(TLSRecordGenStrategy&& rec_strategy, Args&& ... args)
				{
					std::vector<UByte> obj_bytes = TLSPacketGenerator:: template generate_object_bytes<TLSUnderlayingPacketGenerator, Args...>(std::forward<Args>(args)...);
					auto size = static_cast<UShort>(obj_bytes.size());

					TLSRecordType msg_type = TLSPacketGenerator::get_overlay_protocol_type();
					obj_bytes.insert(obj_bytes.begin(), static_cast<UByte>(msg_type));

					auto legacy_version = rec_strategy.get_legacy_version();
					obj_bytes.insert(obj_bytes.begin() + 1, static_cast<UByte>(legacy_version >> 8 & 0xFF));
					obj_bytes.insert(obj_bytes.begin() + 2, static_cast<UByte>(legacy_version & 0xFF));

					obj_bytes.insert(obj_bytes.begin() + 3, static_cast<UByte>(size >> 8 & 0xFF));
					obj_bytes.insert(obj_bytes.begin() + 4, static_cast<UByte>(size & 0xFF));

					return obj_bytes;
				}

				// generator for application data
				template <TLSRecordGenerationStrategy TLSRecordGenStrategy, class TLSPacketGenerator, class ... Args>
					requires TLSPacketGeneratorLike<TLSPacketGenerator, Args...>
				static std::vector<UByte> generate_object_bytes(TLSRecordGenStrategy&& rec_strategy, Args&& ... args)
				{
					std::vector<UByte> obj_bytes = TLSPacketGenerator:: template generate_object_bytes<Args...>(std::forward<Args>(args)...);
					auto size = static_cast<UShort>(obj_bytes.size());

					TLSRecordType msg_type = TLSPacketGenerator::get_overlay_protocol_type();
					obj_bytes.insert(obj_bytes.begin(), static_cast<UByte>(msg_type));

					auto legacy_version = rec_strategy.get_legacy_version();
					obj_bytes.insert(obj_bytes.begin() + 1, static_cast<UByte>(legacy_version >> 8 & 0xFF));
					obj_bytes.insert(obj_bytes.begin() + 2, static_cast<UByte>(legacy_version & 0xFF));

					obj_bytes.insert(obj_bytes.begin() + 3, static_cast<UByte>(size >> 8 & 0xFF));
					obj_bytes.insert(obj_bytes.begin() + 4, static_cast<UByte>(size & 0xFF));

					return obj_bytes;
				}


				// generator for handshake messages
				template <TLSRecordGenerationStrategy TLSRecordGenStrategy, class TLSPacketGenerator, class TLSUnderlayingPacketGenerator, class ... Args>
					requires TLSPacketGeneratorLike<TLSUnderlayingPacketGenerator, Args...> //&& TLSPacketGeneratorLike<TLSPacketGenerator, Args...>
				static TLS13_RecordLittleEndian generate_object(TLSRecordGenStrategy&& strategy, Args&& ... args)
				{
					auto obj_bytes = generate_object_bytes<TLSRecordGenStrategy, TLSPacketGenerator, TLSUnderlayingPacketGenerator, Args...>(std::forward<TLSRecordGenStrategy>(strategy), std::forward<Args>(args)...);
					return TLS13_RecordLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}

				// generator for application data
				template <TLSRecordGenerationStrategy TLSRecordGenStrategy, class TLSPacketGenerator, class ... Args>
					requires TLSPacketGeneratorLike<TLSPacketGenerator, Args...>
				static TLS13_RecordLittleEndian generate_object(TLSRecordGenStrategy&& strategy, Args&& ... args)
				{
					auto obj_bytes = generate_object_bytes<TLSRecordGenStrategy, TLSPacketGenerator, Args...>(std::forward<TLSRecordGenStrategy>(strategy), std::forward<Args>(args)...);
					return TLS13_RecordLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}

				TLSRecordType get_tls_record_type() const;
				TLSProtocolVersion get_tls_protocol_version() const;

				UShort get_tls_record_full_length() const;
				UShort get_tls_record_length() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_record_data() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLS13_RecordView
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

			private:

				UByte* data_;
				UShort size_;

			public:

				template <std::random_access_iterator Iter>
				TLS13_RecordView(Iter begin, Iter end)
				{
					data_ = begin;
					size_ = std::distance(begin, end);
				}

				// generator for handshake messages
				template <TLSRecordGenerationStrategy TLSRecordGenStrategy, class TLSPacketGenerator, class TLSUnderlayingPacketGenerator, class ... Args>
					requires TLSPacketGeneratorLike<TLSUnderlayingPacketGenerator, Args...> //&& TLSPacketGeneratorLike<TLSPacketGenerator, Args...>
				static std::vector<UByte> generate_object_bytes(TLSRecordGenStrategy&& rec_strategy, Args&& ... args)
				{
					return TLS13_RecordLittleEndian::generate_object_bytes<TLSRecordGenStrategy, TLSPacketGenerator, TLSUnderlayingPacketGenerator, Args...>(std::forward<TLSRecordGenStrategy>(rec_strategy), std::forward<Args>(args)...);
				}

				template <TLSRecordGenerationStrategy TLSRecordGenStrategy, class TLSPacketGenerator, class TLSUnderlayingPacketGenerator, class ... Args>
					requires TLSPacketGeneratorLike<TLSUnderlayingPacketGenerator, Args...> //&& TLSPacketGeneratorLike<TLSPacketGenerator, Args...>
				static TLS13_RecordLittleEndian generate_object(TLSRecordGenStrategy&& strategy, Args&& ... args)
				{
					return TLS13_RecordLittleEndian::generate_object<TLSRecordGenStrategy, TLSPacketGenerator, TLSUnderlayingPacketGenerator, Args...>(std::forward<TLSRecordGenStrategy>(strategy), std::forward<Args>(args)...);
				}


				// generators for application data
				template <TLSRecordGenerationStrategy TLSRecordGenStrategy, class TLSPacketGenerator, class ... Args>
				static std::vector<UByte> generate_object_bytes(TLSRecordGenStrategy&& strategy, Args&& ... args)
				{
					return TLS13_RecordLittleEndian::generate_object_bytes<TLSRecordGenStrategy, TLSPacketGenerator, Args...>(std::forward<TLSRecordGenStrategy>(strategy), std::forward<Args>(args)...);
				}

				template <TLSRecordGenerationStrategy TLSRecordGenStrategy, class TLSPacketGenerator, class ... Args>
				static TLS13_RecordLittleEndian generate_object(TLSRecordGenStrategy&& strategy, Args&& ... args)
				{
					return TLS13_RecordLittleEndian::generate_object<TLSRecordGenStrategy, TLSPacketGenerator, Args...>(std::forward<TLSRecordGenStrategy>(strategy), std::forward<Args>(args)...);
				}

				TLSRecordType get_tls_record_type() const;
				TLSProtocolVersion get_tls_protocol_version() const;

				UShort get_tls_record_full_length() const;
				UShort get_tls_record_length() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_record_data() const;
				std::pair<DataIterator_t, DataIterator_t> get_tls_record_data();
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			template <std::integral Val>
			struct TLS13_HelloPacketScheme
			{
				std::pair<Val, Val> random;
				std::pair<Val, Val> session;
				std::pair<Val, Val> ciphers;
				std::pair<Val, Val> compressions;
				std::pair<Val, Val> extensions;
			};


			class TLS13_MessageLittleEndian
			{
			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;
				using OverlayProtocolType = TLSRecordType;

			private:
				std::vector<UByte> data_;

			public:

				TLS13_MessageLittleEndian(UByte* begin, UByte* end);

				TLSMessageType get_tls_msg_type() const;
				UInt get_tls_msg_length() const;
				UInt get_tls_msg_full_length() const;

				static OverlayProtocolType get_overlay_protocol_type();

				template <class TLSPacketGenerator, class TLSGenerationStrategy, class ... Args>
				static std::vector<UByte> generate_object_bytes(TLSGenerationStrategy&& strategy, Args&& ... args)
				{
					std::vector<UByte> obj_bytes = TLSPacketGenerator:: template generate_object_bytes<TLSGenerationStrategy, Args...>(std::forward<TLSGenerationStrategy>(strategy), std::forward<Args>(args)...);
					auto size = static_cast<UInt>(obj_bytes.size());
					TLSMessageType msg_type = TLSPacketGenerator::get_overlay_protocol_type();

					obj_bytes.insert(obj_bytes.begin(), static_cast<UByte>(msg_type));

					obj_bytes.insert(obj_bytes.begin() + 1, static_cast<UByte>(size >> 16 & 0xFF));
					obj_bytes.insert(obj_bytes.begin() + 2, static_cast<UByte>(size >> 8 & 0xFF));
					obj_bytes.insert(obj_bytes.begin() + 3, static_cast<UByte>(size & 0xFF));

					return obj_bytes;
				}

				template <class TLSGenerator, class TLSGenerationStrategy, class ... Args>
				static TLS13_MessageLittleEndian generate_object(TLSGenerationStrategy&& strategy, Args&& ... args)
				{
					auto obj_bytes = generate_object_bytes<TLSGenerator, TLSGenerationStrategy, Args...>(std::forward<TLSGenerationStrategy>(strategy), std::forward<Args>(args)...);
					return TLS13_MessageLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}

				std::pair<DataIterator_t, DataIterator_t> get_tls_msg_data();
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_msg_data() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};

			class TLS13_MessageView
			{
			public:

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;
				using OverlayProtocolType = TLSRecordType;

			private:
				UByte* data_;
				UInt size_;

			public:

				TLS13_MessageView(UByte* begin, UByte* end);

				TLSMessageType get_tls_msg_type() const;
				UInt get_tls_msg_length() const;
				UInt get_tls_msg_full_length() const;


				static OverlayProtocolType get_overlay_protocol_type();

				template <class TLSPacketGenerator, class TLSGenerationStrategy, class ... Args>
				static std::vector<UByte> generate_object_bytes(TLSGenerationStrategy&& strategy, Args&& ... args)
				{
					return TLS13_MessageLittleEndian::generate_object_bytes<TLSPacketGenerator, TLSGenerationStrategy, Args...>(std::forward<TLSGenerationStrategy>(strategy), std::forward<Args>(args)...);
				}

				template <class TLSGenerator, class TLSGenerationStrategy, class ... Args>
				static TLS13_MessageLittleEndian generate_object(TLSGenerationStrategy&& strategy, Args&& ... args)
				{
					return TLS13_MessageLittleEndian::generate_object<TLSGenerator, TLSGenerationStrategy, Args...>(std::forward<TLSGenerationStrategy>(strategy), std::forward<Args>(args)...);
				}


				std::pair<DataIterator_t, DataIterator_t> get_tls_msg_data();
				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_tls_msg_data() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			template <class GenerationStrategyImpl>
			concept TLS13_ClientHelloGenStrategy =
				requires (GenerationStrategyImpl t, std::string_view host) {

					{ t.get_legacy_version() } -> std::same_as<TLSProtocolVersion>;
					{ t.get_session_length() } -> std::same_as<UByte>;
					{ t.get_cipher_length() } -> std::same_as<UShort>;
					{ t.get_compression_length() } -> std::same_as<UShort>;

					// extensions
					// tls sup ver ext
					{ t.get_supported_versions_length() } -> std::same_as<UShort>;
					{ t.get_supported_versions() } -> std::same_as<std::vector<TLSProtocolVersion>>;

					// tls key share client hello ext
					{ t.get_key_share_length() } -> std::same_as<UShort>;
					{ t.get_key_share() } -> std::same_as<std::vector<std::pair<TLSKeyTypes, TLSKeyTypesLength>>>;

					// tls sni ext
					{ t.get_sni_length() } -> std::same_as<UShort>;
					{ t.get_sni_hosts() } -> std::same_as<std::vector<std::string_view>>;
					{ t.get_sni_hosts(host) } -> std::same_as<std::vector<std::string_view>>;
			};

			class TLS13_DefaultClientHelloGenerationStrategy
			{
			public:

				TLSProtocolVersion get_legacy_version() const;

				UByte get_session_length() const;
				UShort get_cipher_length() const;
				UShort get_compression_length() const;

				UShort get_supported_versions_length() const;
				std::vector<TLSProtocolVersion> get_supported_versions() const;

				UShort get_key_share_length() const;
				std::vector<std::pair<TLSKeyTypes, TLSKeyTypesLength>> get_key_share() const;

				UShort get_sni_length() const;
				std::vector<std::string_view> get_sni_hosts() const;
				std::vector<std::string_view> get_sni_hosts(std::string_view host) const;
			};


			class TLS13_ClientHelloPacketLittleEndian
			{

			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;
				using OverlayProtocolType = TLSMessageType;

			private:
				std::vector<UByte> data_;
				TLS13_HelloPacketScheme<size_t> scheme_;

				void parse_scheme();

			public:

				template <std::random_access_iterator Iter>
				TLS13_ClientHelloPacketLittleEndian(Iter begin, Iter end)
				{
					std::copy(begin, end, std::back_inserter(data_));
					parse_scheme();
				}

				bool is_valid() const;

				// generators for qvpn

				template <TLS13_ClientHelloGenStrategy GenStrategy, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
					requires std::is_same_v<Iter1, Iter2>
				static std::vector<UByte> generate_object_bytes(GenStrategy&& strategy, Iter1 begin, Iter2 end)
				{
					std::vector<UByte> obj_bytes;

					// legacy version, must be TLS 1.2
					auto legacy_version = strategy.get_legacy_version();

					obj_bytes.push_back(static_cast<UByte>(legacy_version >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(legacy_version & 0xFF));

					auto random = TLSRandomLittleEndian::generate_object_bytes();
					std::copy(random.begin(), random.end(), std::back_inserter(obj_bytes));

					using Iter = Iter1;

					auto session = TLSSessionIDLittleEndian::generate_object_bytes(begin, end);
					std::copy(session.begin(), session.end(), std::back_inserter(obj_bytes));

					auto cipher = TLSCipherSuitLittleEndian::generate_object_bytes(strategy.get_cipher_length());
					std::copy(cipher.begin(), cipher.end(), std::back_inserter(obj_bytes));

					auto compres = TLSCompressionLittleEndian::generate_object_bytes(strategy.get_compression_length());
					std::copy(compres.begin(), compres.end(), std::back_inserter(obj_bytes));

					auto sup_vers = strategy.get_supported_versions();
					auto key_shares = strategy.get_key_share();
					auto sni_hosts = strategy.get_sni_hosts();

					std::pair<SupVerIter, SupVerIter> vers_iters = std::make_pair<>(sup_vers.begin(), sup_vers.end());
					std::pair<KeyShareIter, KeyShareIter> key_shares_iters = std::make_pair<>(key_shares.begin(), key_shares.end());
					std::pair<SNIIter, SNIIter> hosts_iters = std::make_pair<>(sni_hosts.begin(), sni_hosts.end());

					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSSupportedVersionsClientHelloExtensionLittleEndian, std::pair<SupVerIter, SupVerIter>> sup_ver(vers_iters);
					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSKeyShareClientHelloLittleEndian, std::pair<KeyShareIter, KeyShareIter>> key_share(key_shares_iters);
					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSServerNameIndicationExtensionLittleEndian, std::pair<SNIIter, SNIIter>> sni(hosts_iters);

					auto extensions = TLSExtensionsLittleEndian::generate_object_bytes(std::move(sup_ver), std::move(key_share), std::move(sni));
					//auto extensions = TLSExtensionsLittleEndian::generate_object_bytes(std::move(sup_ver));
					std::copy(extensions.begin(), extensions.end(), std::back_inserter(obj_bytes));

					return obj_bytes;
				}

				template <TLS13_ClientHelloGenStrategy GenStrategy, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
					requires std::is_same_v<Iter1, Iter2>
				static TLS13_ClientHelloPacketLittleEndian generate_object(GenStrategy&& strategy, Iter1 begin, Iter2 end)
				{
					auto obj_bytes = generate_object_bytes<GenStrategy, Iter1, Iter2>(std::forward<GenStrategy>(strategy), begin, end);
					return TLS13_ClientHelloPacketLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}


				template <TLS13_ClientHelloGenStrategy GenStrategy, is_whitelist_data WListData, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
					requires std::is_same_v<Iter1, Iter2>
				static std::vector<UByte> generate_object_bytes(GenStrategy&& strategy, WListData host, Iter1 begin, Iter2 end)
				{
					std::vector<UByte> obj_bytes;

					// legacy version, must be TLS 1.2
					auto legacy_version = strategy.get_legacy_version();

					obj_bytes.push_back(static_cast<UByte>(legacy_version >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(legacy_version & 0xFF));

					auto random = TLSRandomLittleEndian::generate_object_bytes();
					std::copy(random.begin(), random.end(), std::back_inserter(obj_bytes));

					using Iter = Iter1;

					auto session = TLSSessionIDLittleEndian::generate_object_bytes(begin, end);
					std::copy(session.begin(), session.end(), std::back_inserter(obj_bytes));

					auto cipher = TLSCipherSuitLittleEndian::generate_object_bytes(strategy.get_cipher_length());
					std::copy(cipher.begin(), cipher.end(), std::back_inserter(obj_bytes));

					auto compres = TLSCompressionLittleEndian::generate_object_bytes(strategy.get_compression_length());
					std::copy(compres.begin(), compres.end(), std::back_inserter(obj_bytes));

					auto sup_vers = strategy.get_supported_versions();
					auto key_shares = strategy.get_key_share();
					auto sni_hosts = strategy.get_sni_hosts(host);

					std::pair<SupVerIter, SupVerIter> vers_iters = std::make_pair<>(sup_vers.begin(), sup_vers.end());
					std::pair<KeyShareIter, KeyShareIter> key_shares_iters = std::make_pair<>(key_shares.begin(), key_shares.end());
					std::pair<SNIIter, SNIIter> hosts_iters = std::make_pair<>(sni_hosts.begin(), sni_hosts.end());
					auto sni_size = static_cast<UShort>(std::distance(sni_hosts.begin(), sni_hosts.end()));

					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSSupportedVersionsClientHelloExtensionLittleEndian, std::pair<SupVerIter, SupVerIter>> sup_ver(vers_iters);
					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSKeyShareClientHelloLittleEndian, std::pair<KeyShareIter, KeyShareIter>> key_share(key_shares_iters);
					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSServerNameIndicationExtensionLittleEndian, std::pair<SNIIter, SNIIter>> sni(hosts_iters);

					auto extensions = TLSExtensionsLittleEndian::generate_object_bytes(std::move(sup_ver), std::move(key_share), std::move(sni));
					//auto extensions = TLSExtensionsLittleEndian::generate_object_bytes(std::move(sup_ver));
					std::copy(extensions.begin(), extensions.end(), std::back_inserter(obj_bytes));

					return obj_bytes;
				}

				template <TLS13_ClientHelloGenStrategy GenStrategy, is_whitelist_data WListData, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
					requires std::is_same_v<Iter1, Iter2>
				static TLS13_ClientHelloPacketLittleEndian generate_object(GenStrategy&& strategy, WListData host, Iter1 begin, Iter2 end)
				{
					auto obj_bytes = generate_object_bytes<GenStrategy, WListData, Iter1, Iter2>(std::forward<GenStrategy>(strategy), host, begin, end);
					return TLS13_ClientHelloPacketLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}

				// defaults generators

				template <TLS13_ClientHelloGenStrategy GenStrategy>
				static std::vector<UByte> generate_object_bytes(GenStrategy&& strategy)
				{
					std::vector<UByte> obj_bytes;

					// legacy version, must be TLS 1.2
					auto legacy_version = strategy.get_legacy_version();

					obj_bytes.push_back(static_cast<UByte>(legacy_version >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(legacy_version & 0xFF));

					auto random = TLSRandomLittleEndian::generate_object_bytes();
					std::copy(random.begin(), random.end(), std::back_inserter(obj_bytes));

					auto session = TLSSessionIDLittleEndian::generate_object_bytes(strategy.get_session_length());
					std::copy(session.begin(), session.end(), std::back_inserter(obj_bytes));

					auto cipher = TLSCipherSuitLittleEndian::generate_object_bytes(strategy.get_cipher_length());
					std::copy(cipher.begin(), cipher.end(), std::back_inserter(obj_bytes));

					auto compres = TLSCompressionLittleEndian::generate_object_bytes(strategy.get_compression_length());
					std::copy(compres.begin(), compres.end(), std::back_inserter(obj_bytes));

					auto sup_vers = strategy.get_supported_versions();
					auto key_shares = strategy.get_key_share();
					auto sni_hosts = strategy.get_sni_hosts();

					std::pair<SupVerIter, SupVerIter> vers_iters = std::make_pair<>(sup_vers.begin(), sup_vers.end());
					std::pair<KeyShareIter, KeyShareIter> key_shares_iters = std::make_pair<>(key_shares.begin(), key_shares.end());
					std::pair<SNIIter, SNIIter> hosts_iters = std::make_pair<>(sni_hosts.begin(), sni_hosts.end());

					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSSupportedVersionsClientHelloExtensionLittleEndian, std::pair<SupVerIter, SupVerIter>> sup_ver(vers_iters);
					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSKeyShareClientHelloLittleEndian, std::pair<KeyShareIter, KeyShareIter>> key_share(key_shares_iters);
					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSServerNameIndicationExtensionLittleEndian, std::pair<SNIIter, SNIIter>> sni(hosts_iters);

					auto extensions = TLSExtensionsLittleEndian::generate_object_bytes(std::move(sup_ver), std::move(key_share), std::move(sni));
					//auto extensions = TLSExtensionsLittleEndian::generate_object_bytes(std::move(sup_ver));
					std::copy(extensions.begin(), extensions.end(), std::back_inserter(obj_bytes));

					return obj_bytes;
				}

				template <TLS13_ClientHelloGenStrategy GenStrategy>
				static TLS13_ClientHelloPacketLittleEndian generate_object(GenStrategy&& strategy)
				{
					auto obj_bytes = generate_object_bytes<>(std::forward<GenStrategy>(strategy));
					return TLS13_ClientHelloPacketLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}

				static OverlayProtocolType get_overlay_protocol_type();

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
				using OverlayProtocolType = TLSMessageType;

			private:
				UByte* data_;
				UInt size_;
				TLS13_HelloPacketScheme<size_t> scheme_;

				void parse_scheme();

			public:

				template <std::random_access_iterator Iter>
				TLS13_ClientHelloPacketView(Iter begin, Iter end)
				{
					data_ = begin;
					size_ = std::distance(begin, end);
					parse_scheme();
				}

				template <TLS13_ClientHelloGenStrategy GenStrategy, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
				static std::vector<UByte> generate_object_bytes(GenStrategy&& strategy, Iter1 begin, Iter2 end)
				{
					return TLS13_ClientHelloPacketLittleEndian::generate_object_bytes<>(std::forward<GenStrategy>(strategy), begin, end);
				}

				template <TLS13_ClientHelloGenStrategy GenStrategy, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
				static TLS13_ClientHelloPacketLittleEndian generate_object(GenStrategy&& strategy, Iter1 begin, Iter2 end)
				{
					return TLS13_ClientHelloPacketLittleEndian::generate_object<>(std::forward<GenStrategy>(strategy), begin, end);
				}

				template <TLS13_ClientHelloGenStrategy GenStrategy>
				static std::vector<UByte> generate_object_bytes(GenStrategy&& strategy)
				{
					return TLS13_ClientHelloPacketLittleEndian::generate_object_bytes<GenStrategy>(std::forward<GenStrategy>(strategy));
				}

				template <TLS13_ClientHelloGenStrategy GenStrategy>
				static TLS13_ClientHelloPacketLittleEndian generate_object(GenStrategy&& strategy)
				{
					return TLS13_ClientHelloPacketLittleEndian::generate_object<GenStrategy>(std::forward<GenStrategy>(strategy));
				}

				static OverlayProtocolType get_overlay_protocol_type();

				UShort get_tls_version() const;
				TLSRandomView get_tls_random() const;
				TLSSessionIDView get_tls_session() const;
				TLSCipherSuitView get_tls_cipher_suites() const;
				TLSCompressionView get_tls_compression_methods() const;
				TLSExtensionsView get_tls_extensions_data() const;
				TLSServerNameIndicationExtensionView get_tls_sni_data() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			template <class GenerationStrategyImpl>
			concept TLS13_ServerHelloGenStrategy =
				requires (GenerationStrategyImpl t) {

					{ t.get_legacy_version() } -> std::same_as<TLSProtocolVersion>;

					{ t.get_session_length() } -> std::same_as<UByte>;

					{ t.get_cipher_suite() } -> std::same_as<TLSCipherSuite>;
					{ t.get_compression_method() } -> std::same_as<TLSCompressionMethod>;

					// extensions
					// tls sup ver ext
					{ t.get_supported_versions_length() } -> std::same_as<UShort>;
					{ t.get_supported_version() } -> std::same_as<TLSProtocolVersion>;

			};


			class TLS13_DefaultServerHelloGenerationStrategy
			{
			public:
				TLSProtocolVersion get_legacy_version() const;

				UByte get_session_length() const;

				TLSCipherSuite get_cipher_suite() const;
				TLSCompressionMethod get_compression_method() const;

				UShort get_supported_versions_length() const;
				TLSProtocolVersion get_supported_version() const;
			};


			class TLS13_ServerHelloPacketLittleEndian
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;
				using OverlayProtocolType = TLSMessageType;

			private:
				std::vector<UByte> data_;
				TLS13_HelloPacketScheme<size_t> scheme_;

				void parse_scheme();

			public:

				TLS13_ServerHelloPacketLittleEndian(UByte* begin, UByte* end);

				static OverlayProtocolType get_overlay_protocol_type();

				template <TLS13_ServerHelloGenStrategy GenStrategy>
				static std::vector<UByte> generate_object_bytes(GenStrategy&& strategy)
				{
					std::vector<UByte> obj_bytes;

					// legacy version, must be TLS 1.2

					auto legacy_version = strategy.get_legacy_version();

					obj_bytes.push_back(static_cast<UByte>(legacy_version >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(legacy_version & 0xFF));

					auto random = TLSRandomLittleEndian::generate_object_bytes();
					std::copy(random.begin(), random.end(), std::back_inserter(obj_bytes));

					// In server hello must be same as client hello, maybe rework this later
					auto session = TLSSessionIDLittleEndian::generate_object_bytes(strategy.get_session_length());
					std::copy(session.begin(), session.end(), std::back_inserter(obj_bytes));

					auto cipher_suite = strategy.get_cipher_suite();
					obj_bytes.push_back(static_cast<UByte>(cipher_suite >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(cipher_suite & 0xFF));

					auto compres_method = strategy.get_compression_method();
					obj_bytes.push_back(static_cast<UByte>(compres_method & 0xFF));

					auto sup_ver = strategy.get_supported_version();

					TLSExtensionWrapper<TLSExtensionLittleEndian, TLSSupportedVersionsServerHelloExtensionLittleEndian, TLSProtocolVersion> sup_ver_ext(sup_ver);

					auto extensions = TLSExtensionsLittleEndian::generate_object_bytes(std::move(sup_ver_ext));
					std::copy(extensions.begin(), extensions.end(), std::back_inserter(obj_bytes));

					return obj_bytes;
				}

				template <TLS13_ServerHelloGenStrategy GenStrategy>
				static TLS13_ServerHelloPacketLittleEndian generate_object(GenStrategy&& strategy)
				{
					auto obj_bytes = generate_object_bytes<>(std::forward<GenStrategy>(strategy));
					return TLS13_ServerHelloPacketLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}

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
				using OverlayProtocolType = TLSMessageType;

			private:
				UByte* data_;
				UInt size_;
				TLS13_HelloPacketScheme<size_t> scheme_;

				void parse_scheme();

			public:

				TLS13_ServerHelloPacketView(UByte* begin, UByte* end);

				static OverlayProtocolType get_overlay_protocol_type();

				template <TLS13_ServerHelloGenStrategy GenStrategy>
				static std::vector<UByte> generate_object_bytes(GenStrategy&& strategy)
				{
					return TLS13_ServerHelloPacketView::generate_object_bytes<GenStrategy>(std::forward<GenStrategy>(strategy));
				}

				template <TLS13_ServerHelloGenStrategy GenStrategy>
				static TLS13_ServerHelloPacketLittleEndian generate_object(GenStrategy&& strategy)
				{
					return TLS13_ServerHelloPacketLittleEndian::generate_object<GenStrategy>(std::forward<GenStrategy>(strategy));
				}


				UShort get_tls_version() const;
				TLSRandomView get_tls_random() const;
				TLSSessionIDView get_tls_session() const;
				TLSCipherSuite get_tls_cipher_suite() const;
				TLSCompressionMethod get_tls_compression_method() const;
				TLSExtensionsView get_tls_extensions_data() const;

				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLS13_ApplicationDataLittleEndian
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;
				using OverlayProtocolType = TLSRecordType;

			private:

				std::vector<UByte> data_;

			public:

				template <std::random_access_iterator Iter>
				TLS13_ApplicationDataLittleEndian(Iter begin, Iter end)
				{
					std::copy(begin, end, std::back_inserter(data_));
				}

				static OverlayProtocolType get_overlay_protocol_type();

				// generators for qvpn

				template <PacketBuilderDataLike PBData, ProxyDataLike ProxyData, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
					requires std::is_same_v<Iter1, Iter2>
				static std::vector<UByte> generate_object_bytes(const PBData& pb_data, const ProxyData& proxy_data, Iter1 begin, Iter2 end)
				{
					std::vector<UByte> obj_bytes;
					// pb data
					obj_bytes.push_back(pb_data.get_packet_id());

					auto offset = pb_data.get_offset();
					obj_bytes.push_back(static_cast<UByte>(offset >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(offset & 0xFF));

					auto orig_size = pb_data.get_original_size() + proxy_data.get_proxy_data_size();
					obj_bytes.push_back(static_cast<UByte>(orig_size >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(orig_size & 0xFF));

					// proxy data
					obj_bytes.push_back(static_cast<UByte>(proxy_data.get_net_proto()));
					obj_bytes.push_back(static_cast<UByte>(proxy_data.get_transport_proto()));

					auto src_addr = proxy_data.get_src_addr().to_bytes();
					std::copy(src_addr.begin(), src_addr.end(), std::back_inserter(obj_bytes));

					UShort src_port = proxy_data.get_src_port();
					obj_bytes.push_back(static_cast<UByte>(src_port >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(src_port & 0xFF));

					auto dst_addr = proxy_data.get_dst_addr().to_bytes();
					std::copy(dst_addr.begin(), dst_addr.end(), std::back_inserter(obj_bytes));

					UShort dst_port = proxy_data.get_dst_port();
					obj_bytes.push_back(static_cast<UByte>(dst_port >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(dst_port & 0xFF));

					auto [b, e] = proxy_data.get_proto_data_bytes();
					std::copy(b, e, std::back_inserter(obj_bytes));

					// data
					std::copy(begin, end, std::back_inserter(obj_bytes));
					return obj_bytes;
				}

				template <PacketBuilderDataLike PBData, ProxyDataLike ProxyData, std::random_access_iterator Iter1, std::random_access_iterator Iter2 >
				static TLS13_ApplicationDataLittleEndian generate_object(const PBData& pb_data, const ProxyData& proxy_data, Iter1 begin, Iter2 end)
				{
					auto obj_bytes = generate_object_bytes<PBData, ProxyData, Iter1, Iter2>(pb_data, proxy_data, begin, end);
					return TLS13_ApplicationDataLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}


				template <PacketBuilderDataLike PBData, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
					requires std::is_same_v<Iter1, Iter2>
				static std::vector<UByte> generate_object_bytes(const PBData& pb_data, Iter1 begin, Iter2 end)
				{
					std::vector<UByte> obj_bytes;

					// pb data
					obj_bytes.push_back(pb_data.get_packet_id());

					auto offset = pb_data.get_offset();
					obj_bytes.push_back(static_cast<UByte>(offset >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(offset & 0xFF));

					auto orig_size = pb_data.get_original_size();
					obj_bytes.push_back(static_cast<UByte>(orig_size >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(orig_size & 0xFF));

					// data
					std::copy(begin, end, std::back_inserter(obj_bytes));
					return obj_bytes;
				}

				template <PacketBuilderDataLike PBData, std::random_access_iterator Iter1, std::random_access_iterator Iter2 >
				static TLS13_ApplicationDataLittleEndian generate_object(const PBData& pb_data, Iter1 begin, Iter2 end)
				{
					auto obj_bytes = generate_object_bytes<PBData, Iter1, Iter2>(pb_data, begin, end);
					return TLS13_ApplicationDataLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}


				template <ProxyDataLike ProxyData, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
					requires std::is_same_v<Iter1, Iter2>
				static std::vector<UByte> generate_object_bytes(const ProxyData& proxy_data, Iter1 begin, Iter2 end)
				{
					std::vector<UByte> obj_bytes;
					obj_bytes.push_back(static_cast<UByte>(proxy_data.get_net_proto()));
					obj_bytes.push_back(static_cast<UByte>(proxy_data.get_transport_proto()));

					auto src_addr = proxy_data.get_src_addr().to_bytes();
					std::copy(src_addr.begin(), src_addr.end(), std::back_inserter(obj_bytes));

					UShort src_port = proxy_data.get_src_port();
					obj_bytes.push_back(static_cast<UByte>(src_port >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(src_port & 0xFF));

					auto dst_addr = proxy_data.get_dst_addr().to_bytes();
					std::copy(dst_addr.begin(), dst_addr.end(), std::back_inserter(obj_bytes));

					UShort dst_port = proxy_data.get_dst_port();
					obj_bytes.push_back(static_cast<UByte>(dst_port >> 8 & 0xFF));
					obj_bytes.push_back(static_cast<UByte>(dst_port & 0xFF));

					auto [b, e] = proxy_data.get_proto_data();
					std::copy(b, e, std::back_inserter(obj_bytes));

					std::copy(begin, end, std::back_inserter(obj_bytes));
					return obj_bytes;
				}

				template <ProxyDataLike ProxyData, std::random_access_iterator Iter1, std::random_access_iterator Iter2>
				static TLS13_ApplicationDataLittleEndian generate_object(const ProxyData& proxy_data, Iter1 begin, Iter2 end)
				{
					auto obj_bytes = generate_object_bytes<ProxyData, Iter1, Iter2>(proxy_data, begin, end);
					return TLS13_ApplicationDataLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}


				template <std::random_access_iterator Iter1, std::random_access_iterator Iter2>
				static std::vector<UByte> generate_object_bytes(Iter1 begin, Iter2 end)
				{
					std::vector<UByte> obj_bytes;
					std::copy(begin, end, std::back_inserter(obj_bytes));
					return obj_bytes;
				}

				template <std::random_access_iterator Iter1, std::random_access_iterator Iter2>
				static TLS13_ApplicationDataLittleEndian generate_object(Iter1 begin, Iter2 end)
				{
					auto obj_bytes = generate_object_bytes<Iter1, Iter2>(begin, end);
					return TLS13_ApplicationDataLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}

				// default generators

				template <std::random_access_iterator Iter>
				static std::vector<UByte> generate_object_bytes(Iter begin, Iter end)
				{
					std::vector<UByte> obj_bytes;
					std::copy(begin, end, std::back_inserter(obj_bytes));
					return obj_bytes;
				}

				template <std::random_access_iterator Iter>
				static TLS13_ApplicationDataLittleEndian generate_object(Iter begin, Iter end)
				{
					auto obj_bytes = generate_object_bytes<Iter>(begin, end);
					return TLS13_ApplicationDataLittleEndian(obj_bytes.begin(), obj_bytes.end());
				}

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_app_data() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			class TLS13_ApplicationDataView
			{
			public:
				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;
				using OverlayProtocolType = TLSRecordType;

			private:

				UByte* data_;
				UShort size_;

			public:

				template <std::random_access_iterator Iter>
				TLS13_ApplicationDataView(Iter begin, Iter end)
				{
					data_ = begin;
					size_ = std::distance(begin, end);
				}

				static OverlayProtocolType get_overlay_protocol_type();

				// generators for qvpn protocol

				template <ProxyDataLike ProxyData, std::random_access_iterator Iter>
				static std::vector<UByte> generate_object_bytes(const ProxyData& proxy_data, Iter begin, Iter end)
				{
					return TLS13_ApplicationDataLittleEndian::generate_object_bytes<ProxyData, Iter>(proxy_data, begin, end);
				}

				template <ProxyDataLike ProxyData, std::random_access_iterator Iter>
				static TLS13_ApplicationDataLittleEndian generate_object(const ProxyData& proxy_data, Iter begin, Iter end)
				{
					return TLS13_ApplicationDataLittleEndian::generate_object<ProxyData, Iter>(proxy_data, begin, end);
				}

				template <std::random_access_iterator Iter1, std::random_access_iterator Iter2>
				static std::vector<UByte> generate_object_bytes(Iter1 begin, Iter2 end)
				{
					return TLS13_ApplicationDataLittleEndian::generate_object_bytes<Iter1, Iter2>(begin, end);
				}

				template <std::random_access_iterator Iter1, std::random_access_iterator Iter2>
				static TLS13_ApplicationDataLittleEndian generate_object(Iter1 begin, Iter2 end)
				{
					return TLS13_ApplicationDataLittleEndian::generate_object<Iter1, Iter2>(begin, end);
				}

				// default generators

				template <std::random_access_iterator Iter>
				static std::vector<UByte> generate_object_bytes(Iter begin, Iter end)
				{
					return TLS13_ApplicationDataLittleEndian::generate_object_bytes<Iter>(begin, end);
				}

				template <std::random_access_iterator Iter>
				static TLS13_ApplicationDataLittleEndian generate_object(Iter begin, Iter end)
				{
					return TLS13_ApplicationDataLittleEndian::generate_object<Iter>(begin, end);
				}

				std::pair<ConstDataIterator_t, ConstDataIterator_t> get_app_data() const;
				std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const;
			};


			template <class NetLayer>
			concept is_net_layer = Ip4PacketLike<NetLayer> || UnifiedIpPacketLike<NetLayer>;

			template <class TransportLayer>
			concept is_transport_layer = TcpPacketLike<TransportLayer> || UdpPacketLike<TransportLayer> || UnifiedTransportLike<TransportLayer>;

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
					: NetLayer(begin, end), TransportLayer(NetLayer::get_next_protocol_byte(), end), DataLayer(TransportLayer::get_next_protocol_byte(), end) {}

				template <std::random_access_iterator NetIter, std::random_access_iterator TransportIter, std::random_access_iterator DataIter>
				FullPacket(NetIter net_begin, NetIter net_end, TransportIter t_begin, TransportIter t_end, DataIter data_begin, DataIter data_end)
					: NetLayer(net_begin, net_end), TransportLayer(t_begin, t_end), DataLayer(data_begin, data_end)
				{

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




			// QTunnel


			template <class Scheme>
			concept QTunnelSchemeLike =
				requires (const Scheme s) {

					{ s.get_scheme_data_length() } -> std::same_as<UShort>;

			};

			class QTunnelTCPViewScheme
			{
			private:

				UShort length_;
				UByte* data_;

			public:

				QTunnelTCPViewScheme(UByte* begin, UByte* end);

				UInt get_seq() const;
				UInt get_ack() const;
				UByte get_flags() const;

				UByte get_offset() const;
				UShort get_window() const;
				UShort get_urgent_pointer() const;

				std::pair<UByte*, UByte*> get_options() const;

				UShort get_scheme_data_length() const;

				static std::vector<UByte> generate_object_bytes(TcpPacketView tcp_packet);

			};


			class QTunnelUDPViewScheme
			{
			private:
				UShort length_;
				UByte* data_;
			public:
				QTunnelUDPViewScheme(UByte* begin, UByte* end);

				UShort get_length() const;

				UShort get_scheme_data_length() const;

				static std::vector<UByte> generate_object_bytes(UdpPacketView udp_packet);

			};

			struct QTunnelProtoData
			{
				std::vector<UByte> data{}; // 2 byte - length, after array of bytes

			public:

				QTunnelProtoData()
				{
					data.push_back(0);
					data.push_back(0);
				}

				QTunnelProtoData(UShort length, UByte* begin, UByte* end)
				{
					data.push_back(length >> 8 & 0xFF);
					data.push_back(length & 0xFF);
					std::copy(begin, end, std::back_inserter(data));
				}

				QTunnelProtoData(UByte* begin, UByte* end)
				{
					std::copy(begin, end, std::back_inserter(data));
				}

				QTunnelProtoData(QTunnelProtoData&& other) noexcept
				{
					data = std::move(other.data);
				}

				QTunnelProtoData& operator=(QTunnelProtoData&& other) noexcept
				{
					data = std::move(other.data);
					return *this;
				}

				UShort get_length() const
				{
					if (data.size() == 0)
						return 0;
					return static_cast<UShort>(data[0] << 8 | data[1]);
				}

				std::pair<UByte*, UByte*> get_proto_data()
				{
					auto length = get_length();
					auto start = sizeof(length);
					return std::pair<UByte*, UByte*>(data.data() + start, data.data() + data.size());
				}

				std::pair<UByte*, UByte*> to_bytes()
				{
					return std::pair<UByte*, UByte*>(data.data(), data.data() + data.size());
				}

			};


			template <TransportProtocol Proto>
			class QTunnelTransportSchemeAdapter
			{

			};

			template <>
			class QTunnelTransportSchemeAdapter<TransportProtocol::TCP> : public QTunnelTCPViewScheme
			{
			public:
				QTunnelTransportSchemeAdapter(UByte* begin, UByte* end)
					: QTunnelTCPViewScheme(begin, end) {}
			};

			template <>
			class QTunnelTransportSchemeAdapter<TransportProtocol::UDP> : public QTunnelUDPViewScheme
			{
			public:
				QTunnelTransportSchemeAdapter(UByte* begin, UByte* end)
					: QTunnelUDPViewScheme(begin, end) {}
			};

			template <QVPN::Core::is_addr Addr>
			struct QTunnelProxy
			{
			public:
				NetProtocol net_protocol{};
				TransportProtocol transport_protocol{};
				Addr source_addr{};
				UShort source_port{};

				Addr dst_addr{};
				UShort dst_port{};

				mutable QTunnelProtoData proto_data;

			public:

				QTunnelProxy() = default;

				QTunnelProxy(NetProtocol net_p, TransportProtocol transport_p, const Addr& src, UShort src_p, const Addr& dst, UShort dst_p, UByte* begin, UByte* end)
				{
					net_protocol = net_p;
					transport_protocol = transport_p;
					source_addr = src;
					source_port = src_p;
					dst_addr = dst;
					dst_port = dst_p;

					proto_data = QTunnelProtoData(begin, end);
				}

				QTunnelProxy(NetProtocol net_p, TransportProtocol transport_p, const Addr& src, UShort src_p, const Addr& dst, UShort dst_p, QTunnelProtoData&& proto_d)
				{
					net_protocol = net_p;
					transport_protocol = transport_p;
					source_addr = src;
					source_port = src_p;
					dst_addr = dst;
					dst_port = dst_p;

					proto_data = std::move(proto_d);
				}

				NetProtocol get_net_proto() const
				{
					return net_protocol;
				}

				TransportProtocol get_transport_proto() const
				{
					return transport_protocol;
				}

				Addr get_src_addr() const
				{
					return source_addr;
				}

				UShort get_src_port() const
				{
					return source_port;
				}

				Addr get_dst_addr() const
				{
					return dst_addr;
				}

				UShort get_dst_port() const
				{
					return dst_port;
				}

				std::pair<UByte*, UByte*> get_proto_data() const
				{
					//return std::pair<UByte*, UByte*>(proto_data.data.data(), proto_data.data.data() + proto_data.data.size())
					return proto_data.get_proto_data();
				}

				std::pair<UByte*, UByte*> get_proto_data_bytes() const
				{
					return proto_data.to_bytes();
				}

				bool check_validity() const
				{
					bool b = false;
					switch (net_protocol) {
					case IPv4:
						b = true;
						break;
					case IPv6:
						return false; // TODO: доделать ipv6
					case NET_UNDEFINED:
						return false;
						break;
					default:
						return false;
					}

					switch (transport_protocol) {
					case TCP:
						b = true;
						break;
					case UDP:
						b = true;
						break;
					case TRANSPORT_UNDEFINED:
						return false;
					default:
						return false;
					}
					return true;
				}

				UShort get_proxy_data_size() const
				{
					UShort size = sizeof(net_protocol) + sizeof(transport_protocol) + source_addr.get_addr_size() + sizeof(source_port) + dst_addr.get_addr_size() + sizeof(dst_port) + proto_data.get_length() + 2; // 2 - size of proto data length field
					return size;
				}

				static inline QTunnelProxy create_and_inverse_addrs(const QTunnelProxy<Addr>& proxy_data)
				{
					auto [b, e] = proxy_data.get_proto_data_bytes();
					return QTunnelProxy(proxy_data.get_net_proto(), proxy_data.get_transport_proto(), proxy_data.get_dst_addr(), proxy_data.get_dst_port(), proxy_data.get_src_addr(),
						proxy_data.get_src_port(), b, e);
					//return res;
				}

				static inline QTunnelProxy create(const QTunnelProxy<Addr>& proxy_data)
				{
					auto [b, e] = proxy_data.get_proto_data_bytes();
					return QTunnelProxy(proxy_data.get_net_proto(), proxy_data.get_transport_proto(), proxy_data.get_src_addr(), proxy_data.get_src_port(), proxy_data.get_dst_addr(),
						proxy_data.get_dst_port(), b, e);
				}

			};


			template <is_addr Addr>
			class QTunnelData : public QTunnelProxy<Addr>
			{
				std::vector<UByte> data_;
				using ProxyData = QTunnelProxy<Addr>;
			public:

				QTunnelData(std::vector<UByte>&& data) // TODO: перепроверить смещения
					: QTunnelProxy<Addr>()
				{
					data_ = std::move(data);
					ProxyData::net_protocol = static_cast<NetProtocol>(data_[0]);
					ProxyData::transport_protocol = static_cast<TransportProtocol>(data_[1]);
					data_.erase(data_.begin(), data_.begin() + 2);
					switch (ProxyData::net_protocol)
					{

					case NetProtocol::IPv4:
					{
						ProxyData::source_addr = Addr(data_.begin(), data_.begin() + 4);
						ProxyData::source_port = data_[4] << 8 | data_[5];
						ProxyData::dst_addr = Addr(data_.begin() + 6, data_.begin() + 10);
						ProxyData::dst_port = data_[10] << 8 | data_[11];
						break;
					}

					case NetProtocol::IPv6:
					{
						ProxyData::source_addr = Addr(data_.begin(), data_.begin() + 16);
						ProxyData::source_port = data_[16] << 8 | data_[17];
						ProxyData::dst_addr = Addr(data_.begin() + 18, data_.begin() + 34);
						ProxyData::dst_port = data_[34] << 8 | data_[35];
						break;
					}
					}
					auto meta_data_size = ProxyData::source_addr.get_addr_size() * 2 + 4; // 2 addrs (src + dst) and 2 ports (src + dst)
					data_.erase(data_.begin(), data_.begin() + meta_data_size);

					// also proto data

					UShort size = static_cast<UShort>(data_[0] << 8 | data_[1]);
					ProxyData::proto_data = QTunnelProtoData(size, data_.data() + 2, data_.data() + size);
					data_.erase(data_.begin(), data_.begin() + size);

					//ProxyData::source_port = data_[0] << 8 | data_[1];

				}

				std::pair<UByte*, UByte*> get_raw_data()
				{
					auto start = data_.data();
					auto end = data_.data() + data_.size();
					return std::pair<UByte*, UByte*>(start, end);
				}
			};

			using QVPNProxyData_Ipv4 = QTunnelProxy<QVPN::Core::IPv4Address>;


			// Full Packet specs

			// Default specs
			template <>
			class FullPacket<Ipv4Packet, TcpPacket, DataPacket> : public Ipv4Packet, public TcpPacket, public DataPacket
			{
			private:

				using Ipv4Packet::ConstDataIterator_t;
				mutable std::vector<UByte> data_;

			public:

				FullPacket(UByte* begin, UByte* end)
					: Ipv4Packet(begin, end), TcpPacket(Ipv4Packet::get_next_protocol_byte(), end), DataPacket(TcpPacket::get_next_protocol_byte(), end) {}

				template <std::random_access_iterator NetIter, std::random_access_iterator TransportIter, std::random_access_iterator DataIter>
				FullPacket(NetIter net_begin, NetIter net_end, TransportIter t_begin, TransportIter t_end, DataIter data_begin, DataIter data_end)
					: Ipv4Packet(net_begin, net_end), TcpPacket(t_begin, t_end), DataPacket(data_begin, data_end)
				{

				}

				std::pair<FullPacket::ConstDataIterator_t, FullPacket::ConstDataIterator_t> bytes() const
				{
					data_.clear();
					auto [b1, e1] = Ipv4Packet::to_bytes();
					std::copy(b1, e1, std::back_inserter(data_));

					auto [b2, e2] = TcpPacket::to_bytes();
					std::copy(b2, e2, std::back_inserter(data_));

					auto [b3, e3] = DataPacket::to_bytes();
					std::copy(b3, e3, std::back_inserter(data_));

					return std::make_pair<>(data_.data(), data_.data() + data_.size());
				}

				UShort get_full_packet_length() const
				{
					auto size = Ipv4Packet::get_ip_total_length();
					return size;
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

				template <std::random_access_iterator Iter>
				FullPacket new_packet_by_payload(Iter begin, Iter end) const
				{
					auto [n_b, n_e] = Ipv4Packet::to_bytes();
					auto [t_b, t_e] = TcpPacket::to_bytes();
					FullPacket fp(n_b, n_e, t_b, t_e, begin, end);
					auto size = static_cast<UShort>(std::distance(begin, end));
					fp.set_transport_length(size);
					fp.recalculate_checksums();
					return fp;
				}

				QTunnelProtoData collect_proto_data()
				{
					auto tcp_view = TcpPacket::to_view();
					auto bytes = QTunnelTCPViewScheme::generate_object_bytes(tcp_view);
					QTunnelProtoData res(bytes.data(), bytes.data() + bytes.size());
					return res;
				}

				void set_qtunnel_proto_data(QTunnelProtoData& data)
				{
					auto [b, e] = data.get_proto_data();
					QTunnelTCPViewScheme scheme(b, e);
					set_tcp_seq_number(scheme.get_seq());
					set_tcp_ack_number(scheme.get_ack());
					set_tcp_flags(scheme.get_flags());

					set_tcp_offset(scheme.get_offset());
					set_tcp_window(scheme.get_window());
					set_tcp_urgent(scheme.get_urgent_pointer());
				}

				void set_qtunnel_proto_data(UByte* begin, UByte* end)
				{
					QTunnelTCPViewScheme scheme(begin, end);
					set_tcp_seq_number(scheme.get_seq());
					set_tcp_ack_number(scheme.get_ack());
					set_tcp_flags(scheme.get_flags());

					set_tcp_offset(scheme.get_offset());
					set_tcp_window(scheme.get_window());
					set_tcp_urgent(scheme.get_urgent_pointer());
				}

				std::string to_packet_friendly_view() const
				{
					std::stringstream ss{};

					auto net = to_net_friendly_view();
					auto transport = to_transport_friendly_view();
					auto data = to_data_friendly_view();

					ss << net << transport << data << std::endl;

					auto str = ss.str();
					return str;
				}

			};

			template <>
			class FullPacket<Ipv4Packet, UdpPacket, DataPacket> : public Ipv4Packet, public UdpPacket, public DataPacket
			{
			private:

				mutable std::vector<UByte> data_;

			public:

				FullPacket(UByte* begin, UByte* end)
					: Ipv4Packet(begin, end), UdpPacket(Ipv4Packet::get_next_protocol_byte(), end), DataPacket(UdpPacket::get_next_protocol_byte(), end) {}

				template <std::random_access_iterator NetIter, std::random_access_iterator TransportIter, std::random_access_iterator DataIter>
				FullPacket(NetIter net_begin, NetIter net_end, TransportIter t_begin, TransportIter t_end, DataIter data_begin, DataIter data_end)
					: Ipv4Packet(net_begin, net_end), UdpPacket(t_begin, t_end), DataPacket(data_begin, data_end)
				{

				}

				std::pair<Ipv4Packet::ConstDataIterator_t, Ipv4Packet::ConstDataIterator_t> bytes() const
				{
					auto [b1, e1] = Ipv4Packet::to_bytes();
					std::copy(b1, e1, std::back_inserter(data_));

					auto [b2, e2] = UdpPacket::to_bytes();
					std::copy(b2, e2, std::back_inserter(data_));

					auto [b3, e3] = DataPacket::to_bytes();
					std::copy(b3, e3, std::back_inserter(data_));

					return std::make_pair<>(data_.data(), data_.data() + data_.size());
				}


				UShort get_full_packet_length() const
				{
					auto size = Ipv4Packet::get_ip_total_length();
					return size;
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

				template <std::random_access_iterator Iter>
				FullPacket new_packet_by_payload(Iter begin, Iter end) const
				{
					auto [n_b, n_e] = Ipv4Packet::to_bytes();
					auto [t_b, t_e] = UdpPacket::to_bytes();
					FullPacket fp(n_b, n_e, t_b, t_e, begin, end);
					auto size = static_cast<UShort>(std::distance(begin, end));
					fp.set_transport_length(size);
					fp.recalculate_checksums();
					return fp;
				}

				QTunnelProtoData collect_proto_data()
				{
					auto view = UdpPacket::to_view();
					auto bytes = QTunnelUDPViewScheme::generate_object_bytes(view);
					QTunnelProtoData res(bytes.data(), bytes.data() + bytes.size());
					return res;
				}

				void set_qtunnel_proto_data(QTunnelProtoData& data)
				{
					auto [b, e] = data.get_proto_data();
					QTunnelTCPViewScheme scheme(b, e);
				}

				void set_qtunnel_proto_data(UByte* begin, UByte* end)
				{
					QTunnelTCPViewScheme scheme(begin, end);
				}

				std::string to_packet_friendly_view() const
				{
					std::stringstream ss{};

					auto net = to_net_friendly_view();
					auto transport = to_transport_friendly_view();
					auto data = to_data_friendly_view();

					ss << net << transport << data << std::endl;

					auto str = ss.str();
					return str;
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

				template <std::random_access_iterator NetIter, std::random_access_iterator TransportIter, std::random_access_iterator DataIter>
				FullPacket(NetIter net_begin, NetIter net_end, TransportIter t_begin, TransportIter t_end, DataIter data_begin, DataIter data_end)
					: Ipv4Packet_View(net_begin, net_end), TcpPacket_View(t_begin, t_end), DataPacket_View(data_begin, data_end)
				{

				}

				std::pair<FullPacket::ConstDataIterator_t, FullPacket::ConstDataIterator_t> bytes() const
				{
					auto [b1, e1] = Ipv4Packet_View::to_bytes();
					auto [b2, e2] = TcpPacket_View::to_bytes();
					auto [b3, e3] = DataPacket_View::to_bytes();
					return std::make_pair<>(b1, e3);
				}

				UShort get_full_packet_length() const
				{
					auto size = Ipv4Packet_View::get_ip_total_length();
					return size;
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

				template <std::random_access_iterator Iter>
				FullPacket new_packet_by_payload(Iter begin, Iter end) const
				{
					auto [n_b, n_e] = Ipv4Packet_View::to_bytes();
					auto [t_b, t_e] = TcpPacket_View::to_bytes();
					FullPacket fp(n_b, n_e, t_b, t_e, begin, end);
					auto size = static_cast<UShort>(std::distance(begin, end));
					fp.set_transport_length(size);
					fp.recalculate_checksums();
					return fp;
				}

				QTunnelProtoData collect_proto_data()
				{
					auto tcp_view = TcpPacket_View::to_view();
					auto bytes = QTunnelTCPViewScheme::generate_object_bytes(tcp_view);
					QTunnelProtoData res(bytes.data(), bytes.data() + bytes.size());
					return res;
				}

				void set_qtunnel_proto_data(QTunnelProtoData& data)
				{
					auto [b, e] = data.get_proto_data();
					QTunnelTCPViewScheme scheme(b, e);
					set_tcp_seq_number(scheme.get_seq());
					set_tcp_ack_number(scheme.get_ack());
					set_tcp_flags(scheme.get_flags());

					set_tcp_offset(scheme.get_offset());
					set_tcp_window(scheme.get_window());
					set_tcp_urgent(scheme.get_urgent_pointer());
				}

				void set_qtunnel_proto_data(UByte* begin, UByte* end)
				{
					QTunnelTCPViewScheme scheme(begin, end);
					set_tcp_seq_number(scheme.get_seq());
					set_tcp_ack_number(scheme.get_ack());
					set_tcp_flags(scheme.get_flags());

					set_tcp_offset(scheme.get_offset());
					set_tcp_window(scheme.get_window());
					set_tcp_urgent(scheme.get_urgent_pointer());
				}

				std::string to_packet_friendly_view() const
				{
					std::stringstream ss{};

					auto net = to_net_friendly_view();
					auto transport = to_transport_friendly_view();
					auto data = to_data_friendly_view();

					ss << net << transport << data << std::endl;

					auto str = ss.str();
					return str;
				}

			};

			template <>
			class FullPacket<Ipv4Packet_View, UdpPacket_View, DataPacket_View> : public Ipv4Packet_View, public UdpPacket_View, public DataPacket_View
			{
			private:

				using Ipv4PacketView::ConstDataIterator_t;

			public:

				FullPacket(UByte* begin, UByte* end)
					: Ipv4Packet_View(begin, end), UdpPacket_View(Ipv4Packet_View::get_next_protocol_byte(), end), DataPacket_View(UdpPacketView::get_next_protocol_byte(), end) {}

				template <std::random_access_iterator NetIter, std::random_access_iterator TransportIter, std::random_access_iterator DataIter>
				FullPacket(NetIter net_begin, NetIter net_end, TransportIter t_begin, TransportIter t_end, DataIter data_begin, DataIter data_end)
					: Ipv4Packet_View(net_begin, net_end), UdpPacket_View(t_begin, t_end), DataPacket_View(data_begin, data_end)
				{

				}

				std::pair<FullPacket::ConstDataIterator_t, FullPacket::ConstDataIterator_t> bytes() const
				{
					auto [b1, e1] = Ipv4Packet_View::to_bytes();
					auto [b2, e2] = UdpPacket_View::to_bytes();
					auto [b3, e3] = DataPacket_View::to_bytes();
					return std::make_pair<>(b1, e3);
				}


				UShort get_full_packet_length() const
				{
					auto size = Ipv4Packet_View::get_ip_total_length();
					return size;
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
					UdpPacketView::recalculate_transport_checksum(pseudo, b, e);
				}

				template <std::random_access_iterator Iter>
				FullPacket new_packet_by_payload(Iter begin, Iter end) const
				{
					auto [n_b, n_e] = Ipv4Packet_View::to_bytes();
					auto [t_b, t_e] = UdpPacket_View::to_bytes();
					FullPacket fp(n_b, n_e, t_b, t_e, begin, end);
					auto size = static_cast<UShort>(std::distance(begin, end));
					fp.set_transport_length(size);
					fp.recalculate_checksums();
					return fp;
				}

				QTunnelProtoData collect_proto_data()
				{
					auto view = UdpPacket_View::to_view();
					auto bytes = QTunnelUDPViewScheme::generate_object_bytes(view);
					QTunnelProtoData res(bytes.data(), bytes.data() + bytes.size());
					return res;
				}

				void set_qtunnel_proto_data(QTunnelProtoData& data)
				{
					auto [b, e] = data.get_proto_data();
					QTunnelTCPViewScheme scheme(b, e);
				}

				void set_qtunnel_proto_data(UByte* begin, UByte* end)
				{
					QTunnelTCPViewScheme scheme(begin, end);
				}

				std::string to_packet_friendly_view() const
				{
					std::stringstream ss{};

					auto net = to_net_friendly_view();
					auto transport = to_transport_friendly_view();
					auto data = to_data_friendly_view();

					ss << net << transport << data << std::endl;

					auto str = ss.str();
					return str;
				}

			};



			// Default instances
			template class FullPacket<Ipv4Packet, TcpPacket, DataPacket>;
			template class FullPacket<Ipv4Packet, UdpPacket, DataPacket>;

			// View instances
			template class FullPacket<Ipv4Packet_View, TcpPacket_View, DataPacket_View>;
			template class FullPacket<Ipv4Packet_View, UdpPacket_View, DataPacket_View>;


			// Dummy spec
			template <>
			class FullPacket<DummyNetPacket, DummyTransportPacket, DummyDataPacket> : public DummyNetPacket, public DummyTransportPacket, public DummyDataPacket
			{
			private:


			public:
				
				FullPacket() = default;

				template <std::random_access_iterator Iter>
				FullPacket(Iter begin, Iter end)
				{

				}

				using DataIterator_t = UByte*;
				using ConstDataIterator_t = const UByte*;

				// Full packet interface
				//////////////////
				std::pair<ConstDataIterator_t, ConstDataIterator_t> bytes() const
				{
					return std::make_pair<ConstDataIterator_t, ConstDataIterator_t>(static_cast<ConstDataIterator_t>(nullptr), static_cast<ConstDataIterator_t>(nullptr));
				}

				UShort get_full_packet_length() const
				{
					return 0;
				}

				void recalculate_checksums()
				{
					
				}

				QTunnelProtoData collect_proto_data()
				{
					return QTunnelProtoData();
				}

				void set_qtunnel_proto_data(QTunnelProtoData& data)
				{

				}

				void set_qtunnel_proto_data(UByte* begin, UByte* end)
				{

				}

				std::string to_packet_friendly_view() const
				{
					return std::string("That`s a dummy packet. If you see this, you doing something wrong.");
				}

			};


			// Dummy instance
			template class FullPacket<DummyNetPacket, DummyTransportPacket, DummyDataPacket>;
			
			// pseudonym for dummy
			using DummyFullPacket = FullPacket<DummyNetPacket, DummyTransportPacket, DummyDataPacket>;



			template <class TransportDataPacketImpl>
			concept NoNetPacketLike = is_transport_layer<TransportDataPacketImpl> && is_data_layer<TransportDataPacketImpl>;

			template <is_transport_layer TransportPacket, is_data_layer DataPacket>
			class NoNetPacket : public TransportPacket, public DataPacket
			{
			public:

				using DataIterator_t = TransportPacket::DataIterator_t;
				using ConstDataIterator_t = TransportPacket::ConstDataIterator_t;

			public:

				template <std::random_access_iterator Iter>
				NoNetPacket(Iter begin, Iter end)
					: TransportPacket(begin, end), DataPacket(TransportPacket::get_next_protocol_byte(), end)
				{

				}

			};


			// Default specs for NoNetPacket
			template <>
			class NoNetPacket<TcpPacket, DataPacket> : public TcpPacket, public DataPacket
			{

			private:

				mutable std::vector<UByte> data_{};

			public:

				using ConstDataIterator_t = const UByte*;

			public:
				template <std::random_access_iterator Iter>
				NoNetPacket(Iter begin, Iter end)
					: TcpPacket(begin, end), DataPacket(TcpPacket::get_next_protocol_byte(), end)
				{

				}

				template <std::random_access_iterator Iter>
				NoNetPacket(Iter transport_begin, Iter transport_end, Iter begin, Iter end)
					: TcpPacket(transport_begin, transport_end), DataPacket(begin, end)
				{

				}

				std::pair<NoNetPacket::ConstDataIterator_t, NoNetPacket::ConstDataIterator_t> bytes() const
				{
					auto [t_b, t_e] = TcpPacket::to_bytes();
					auto [d_b, d_e] = TcpPacket::to_bytes();
					std::copy(t_b, t_e, std::back_inserter(data_));
					std::copy(d_b, d_e, std::back_inserter(data_));
					ConstDataIterator_t start = data_.data();
					ConstDataIterator_t end = data_.data() + data_.size();
					return std::pair<ConstDataIterator_t, ConstDataIterator_t>(start, end);
				}

				void recalculate_checksums(const NetAddr& src, const NetAddr& dst, UShort length)
				{
					NetProtocol net_proto = src.get_addr_family();
					auto [b, e] = DataPacket::get_data();
					switch (net_proto)
					{
					case IPv4:
					{
						auto src4 = src.to_ipv4();
						auto dst4 = dst.to_ipv4();
						TransportIpv4PseudoHeader pseudo(src4, dst4, static_cast<UByte>(net_proto), length);
						TcpPacket::recalculate_transport_checksum(pseudo, b, e);
						break;
					}
					default:
						break;
					}
				}

				template <std::random_access_iterator Iter>
				NoNetPacket new_packet_by_payload(const NetAddr& src, const NetAddr& dst, UShort length, Iter begin, Iter end) const
				{
					auto [t_b, t_e] = TcpPacket::to_bytes();
					NoNetPacket np(t_b, t_e, begin, end);
					auto size = static_cast<UShort>(std::distance(begin, end));
					np.set_transport_length(size);
					np.recalculate_checksums(src, dst, length);
					return np;
				}

				void set_seq_ack_flags(UInt seq, UInt ack, UByte flags)
				{
					TcpPacket::set_tcp_seq_number(seq);
					TcpPacket::set_tcp_ack_number(ack);
					TcpPacket::set_tcp_flags(flags);
				}

			};

			template <>
			class NoNetPacket<UdpPacket, DataPacket> : public UdpPacket, public DataPacket
			{
			private:

				mutable std::vector<UByte> data_{};

			public:

				using ConstDataIterator_t = const UByte*;

			public:
				template <std::random_access_iterator Iter>
				NoNetPacket(Iter begin, Iter end)
					: UdpPacket(begin, end), DataPacket(UdpPacket::get_next_protocol_byte(), end)
				{

				}

				template <std::random_access_iterator Iter>
				NoNetPacket(Iter transport_begin, Iter transport_end, Iter begin, Iter end)
					: UdpPacket(transport_begin, transport_end), DataPacket(begin, end)
				{

				}

				std::pair<NoNetPacket::ConstDataIterator_t, NoNetPacket::ConstDataIterator_t> bytes() const
				{
					auto [t_b, t_e] = UdpPacket::to_bytes();
					auto [d_b, d_e] = UdpPacket::to_bytes();
					std::copy(t_b, t_e, std::back_inserter(data_));
					std::copy(d_b, d_e, std::back_inserter(data_));
					return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data_.data(), data_.data() + data_.size());
				}

				void recalculate_checksums(const NetAddr& src, const NetAddr& dst, UShort length)
				{
					NetProtocol net_proto = src.get_addr_family();
					auto [b, e] = DataPacket::get_data();
					switch (net_proto)
					{
					case IPv4:
					{
						auto src4 = src.to_ipv4();
						auto dst4 = dst.to_ipv4();
						TransportIpv4PseudoHeader pseudo(src4, dst4, static_cast<UByte>(net_proto), length);
						UdpPacket::recalculate_transport_checksum(pseudo, b, e);
						break;
					}
					default:
						break;
					}
				}

				template <std::random_access_iterator Iter>
				NoNetPacket new_packet_by_payload(const NetAddr& src, const NetAddr& dst, UShort length, Iter begin, Iter end) const
				{
					auto [t_b, t_e] = UdpPacket::to_bytes();
					NoNetPacket np(t_b, t_e, begin, end);
					auto size = static_cast<UShort>(std::distance(begin, end));
					np.set_transport_length(size);
					np.recalculate_checksums(src, dst, length);
					return np;
				}

				void set_seq_ack_flags(UInt seq, UInt ack, UByte flags)
				{

				}
			};

			// Views specs for no net packet

			template <>
			class NoNetPacket<TcpPacket_View, DataPacket_View> : public TcpPacket_View, public DataPacket_View
			{

			public:

				using ConstDataIterator_t = TcpPacket_View::ConstDataIterator_t;

			public:
				template <std::random_access_iterator Iter>
				NoNetPacket(Iter begin, Iter end)
					: TcpPacket_View(begin, end), DataPacket_View(TcpPacket_View::get_next_protocol_byte(), end)
				{

				}

				template <std::random_access_iterator Iter>
				NoNetPacket(Iter transport_begin, Iter transport_end, Iter begin, Iter end)
					: TcpPacket_View(transport_begin, transport_end), DataPacket_View(begin, end)
				{

				}

				std::pair<NoNetPacket::ConstDataIterator_t, NoNetPacket::ConstDataIterator_t> bytes() const
				{
					auto [t_b, t_e] = TcpPacket_View::to_bytes();
					auto [d_b, d_e] = TcpPacket_View::to_bytes();
					return std::pair<ConstDataIterator_t, ConstDataIterator_t>(t_b, d_e);
				}

				void recalculate_checksums(const NetAddr& src, const NetAddr& dst, UShort length)
				{
					NetProtocol net_proto = src.get_addr_family();
					auto [b, e] = DataPacket_View::get_data();
					switch (net_proto)
					{
					case IPv4:
					{
						auto src4 = src.to_ipv4();
						auto dst4 = dst.to_ipv4();
						TransportIpv4PseudoHeader pseudo(src4, dst4, static_cast<UByte>(net_proto), length);
						TcpPacket_View::recalculate_transport_checksum(pseudo, b, e);
						break;
					}
					default:
						break;
					}
				}

				template <std::random_access_iterator Iter>
				NoNetPacket new_packet_by_payload(const NetAddr& src, const NetAddr& dst, UShort length, Iter begin, Iter end) const
				{
					auto [t_b, t_e] = TcpPacket_View::to_bytes();
					NoNetPacket np(t_b, t_e, begin, end);
					auto size = static_cast<UShort>(std::distance(begin, end));
					np.set_transport_length(size);
					np.recalculate_checksums(src, dst, length);
					return np;
				}

				void set_seq_ack_flags(UInt seq, UInt ack, UByte flags)
				{
					TcpPacket_View::set_tcp_seq_number(seq);
					TcpPacket_View::set_tcp_ack_number(ack);
					TcpPacket_View::set_tcp_flags(flags);
				}

			};


			template <>
			class NoNetPacket<UdpPacket_View, DataPacket_View> : public UdpPacket_View, public DataPacket_View
			{
			public:

				using ConstDataIterator_t = UdpPacket_View::ConstDataIterator_t;

			public:
				template <std::random_access_iterator Iter>
				NoNetPacket(Iter begin, Iter end)
					: UdpPacket_View(begin, end), DataPacket_View(UdpPacket_View::get_next_protocol_byte(), end)
				{

				}

				template <std::random_access_iterator Iter>
				NoNetPacket(Iter transport_begin, Iter transport_end, Iter begin, Iter end)
					: UdpPacket_View(transport_begin, transport_end), DataPacket_View(begin, end)
				{

				}

				std::pair<NoNetPacket::ConstDataIterator_t, NoNetPacket::ConstDataIterator_t> bytes() const
				{
					auto [t_b, t_e] = UdpPacket_View::to_bytes();
					auto [d_b, d_e] = UdpPacket_View::to_bytes();
					return std::pair<ConstDataIterator_t, ConstDataIterator_t>(t_b, d_e);
				}

				void recalculate_checksums(const NetAddr& src, const NetAddr& dst, UShort length)
				{
					NetProtocol net_proto = src.get_addr_family();
					auto [b, e] = DataPacket_View::get_data();
					switch (net_proto)
					{
					case IPv4:
					{
						auto src4 = src.to_ipv4();
						auto dst4 = dst.to_ipv4();
						TransportIpv4PseudoHeader pseudo(src4, dst4, static_cast<UByte>(net_proto), length);
						UdpPacket_View::recalculate_transport_checksum(pseudo, b, e);
						break;
					}
					default:
						break;
					}
				}

				template <std::random_access_iterator Iter>
				NoNetPacket new_packet_by_payload(const NetAddr& src, const NetAddr& dst, UShort length, Iter begin, Iter end) const
				{
					auto [t_b, t_e] = UdpPacket_View::to_bytes();
					NoNetPacket np(t_b, t_e, begin, end);
					auto size = static_cast<UShort>(std::distance(begin, end));
					np.set_transport_length(size);
					np.recalculate_checksums(src, dst, length);
					return np;
				}

				void set_seq_ack_flags(UInt seq, UInt ack, UByte flags)
				{

				}
			};


			// Default instances for no net packet
			template class NoNetPacket<TcpPacket, DataPacket>;
			template class NoNetPacket<UdpPacket, DataPacket>;

			using NoNetPacketTcpObject = NoNetPacket<TcpPacket, DataPacket>;
			using NoNetPacketUdpObject = NoNetPacket<UdpPacket, DataPacket>;

			// View instances for no net packet
			template class NoNetPacket<TcpPacket_View, DataPacket_View>;
			template class NoNetPacket<UdpPacket_View, DataPacket_View>;

			using NoNetPacketTcpView = NoNetPacket<TcpPacket_View, DataPacket_View>;
			using NoNetPacketUdpView = NoNetPacket<UdpPacket_View, DataPacket_View>;

		}
	}
}

