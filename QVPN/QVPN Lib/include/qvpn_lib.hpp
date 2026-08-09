#pragma once
#include <qvpn_general.hpp>
#include <array>
#include <unordered_map>
#include <iterator>
#include <iostream>
#include <sstream>
#include <format>


namespace QVPN
{
	namespace Core
	{

		namespace BaseTypes
		{
			using Byte = char;
			using UByte = unsigned char;
			using UShort = unsigned short;
			using UInt = unsigned int;
			using ULong = unsigned long long;
			using Long = long long;
			using ubyte_const_iter = std::vector<unsigned char>::const_iterator;
		}

		class QVPNLib
		{
			using UInt = BaseTypes::UInt;

			static constexpr std::string_view lib_name_ = "QVPN Library/Framework";
			static constexpr std::string_view short_lib_name_ = "QVPN Lib";

			static constexpr UInt major_ver_ = 0;
			static constexpr UInt minor_ver_ = 5;
			static constexpr UInt patch_ver_ = 5;

			//static constexpr std::string_view lib_ver_ = "0.5.5";

			//static constexpr std::string_view full_lib_name_ = "QVPN Library v0.5.5";

			static constexpr UInt last_compatible_major_ver_ = 0;
			static constexpr UInt last_compatible_minor_ver_ = 5;
			static constexpr UInt last_compatible_patch_ver_ = 0;

		private:
			template<typename T>
			constexpr static std::string u_number_to_string(T value)
			{
				T temp = value;
				constexpr UInt max_size = 20; //(максимум 20 цифр для 64 - битного числа)

				// Обрабатываем 0 отдельно
				if (temp == 0) {
					return "0";
				}

				// Создаем строку из буфера
				std::string result;
				while (temp != 0) {
					auto t = temp % 10;
					temp /= 10;
					result += static_cast<UInt>(t);
				}

				return result;
			}


		public:
			consteval std::string_view get_short_library_name() const;
			consteval std::string_view get_library_name() const;
			consteval UInt get_major_version() const;
			consteval UInt get_minor_version() const;
			consteval UInt get_patch_version() const;
			constexpr std::string get_library_version() const;
			constexpr std::string get_full_library_name() const;
			consteval bool is_compatible(UInt major, UInt minor, UInt patch) const;
		};


		enum LoggerVerboseLevel : BaseTypes::UByte
		{
			SILENCE = 0,

			IMPORTANT = 0x1, // success and fails
			WARNING = 0x2,  // warnings
			INFO = 0x4, // info

			IMPORTANT_AND_WARNING = IMPORTANT | WARNING,
			WARNING_AND_INFO = WARNING | INFO,
			IMPORTANT_AND_INFO = IMPORTANT | INFO,

			ALL = IMPORTANT | WARNING | INFO
		};


		namespace details
		{
			class DummyArg {};
			class DummyArg1 {};
			class DummyArg2 {};
		}

		template <class LoggerImpl>
		concept is_logger =
			requires (LoggerImpl l, std::string_view data, LoggerVerboseLevel level, details::DummyArg arg1, details::DummyArg1 arg2, details::DummyArg2 arg3) {

				{ l.info(data) } -> std::same_as<void>;
				{ l.info(data, arg1, arg2, arg3) } -> std::same_as<void>;
				{ l.success(data) } -> std::same_as<void>;
				{ l.success(data, arg1, arg2, arg3) } -> std::same_as<void>;
				{ l.fail(data) } -> std::same_as<void>;
				{ l.fail(data, arg1, arg2, arg3) } -> std::same_as<void>;
				{ l.warning(data) } -> std::same_as<void>;
				{ l.warning(data, arg1, arg2, arg3) } -> std::same_as<void>;

				{ l.set_verbosity(level) } -> std::same_as<void>;

				{ l.set_prefix(data) } -> std::same_as<void>;
				{ l.clear_prefix() } -> std::same_as<void>;
		};


		enum class QVPNPlatform
		{
			WINDOWS = 0,
			LINUX = 1,
			ANDROID = 2,
		};

		enum QVPNAppType
		{
			UNDEFINED = -1,
			CLIENT = 0,
			SERVER = 1
			
		};

		enum QVPNClientWorkMode
		{
			CLIENT_VPN = 0, // vpn mode
			CLIENT_PROXY_NODE = 1, // send data through server proxy node, no traffic modification
			CLIENT_ANTI_DPI_NODE = 2, // send data through server proxy node with "broken" headers
			CLIENT_ANTI_DPI = 3, // dpi bypass, works without server
			CLIENT_DPI_TERROR = 99, // DPI Terror mode, spam packets (must use for turn on bypass mode on DPI, needed many many many clients\servers with this mode)
		};

		enum QVPNServerWorkMode
		{
			SERVER_VPN = 0, // vpn mode
			SERVER_PROXY_NODE = 1, // receive data from client with CLIENT_PROXY_NODE and resend to original destination
			SERVER_ANTI_DPI_NODE = 2, // receive data from client with CLIENT_ANTI_DPI_NODE, fix packet and send to original destination
			SERVER_DPI_TERROR = 99, // DPI Terror mode, spam packets (must use for turn on bypass mode on DPI, needed many many many clients\servers with this mode)
		};

	}

}

namespace std {
	template<>
	struct hash<QVPN::Core::QVPNClientWorkMode> {
		size_t operator()(const QVPN::Core::QVPNClientWorkMode& obj) const {
			return hash<int>()(static_cast<int>(obj));
		}
	};

	template<>
	struct hash<QVPN::Core::QVPNServerWorkMode> {
		size_t operator()(const QVPN::Core::QVPNServerWorkMode& obj) const {
			return hash<int>()(static_cast<int>(obj));
		}
	};
}

namespace QVPN {

	namespace Core {


		class QVPNModeVerbose
		{
		private:
			static inline std::unordered_map<QVPNClientWorkMode, std::string_view> client_verboses_ = { {QVPNClientWorkMode::CLIENT_VPN, "QVPN Mode"}, {QVPNClientWorkMode::CLIENT_PROXY_NODE, "Proxy Mode"},
				{QVPNClientWorkMode::CLIENT_ANTI_DPI_NODE, "Anti DPI through server Mode"}, {QVPNClientWorkMode::CLIENT_ANTI_DPI, "Anti DPI Mode"}, {QVPNClientWorkMode::CLIENT_DPI_TERROR, "DPI Terror Mode"} };

			static inline std::unordered_map<std::string_view, QVPNClientWorkMode> client_modes_ = { {"QVPN Mode", QVPNClientWorkMode::CLIENT_VPN}, {"Proxy Mode", QVPNClientWorkMode::CLIENT_PROXY_NODE},
				{"Anti DPI through server Mode", QVPNClientWorkMode::CLIENT_ANTI_DPI_NODE}, {"Anti DPI Mode", QVPNClientWorkMode::CLIENT_ANTI_DPI}, {"DPI Terror Mode", QVPNClientWorkMode::CLIENT_DPI_TERROR} };

			static inline std::unordered_map<QVPNServerWorkMode, std::string_view> server_verboses_ = { {QVPNServerWorkMode::SERVER_VPN, "QVPN Mode"}, {QVPNServerWorkMode::SERVER_PROXY_NODE, "Proxy Mode"},
				{QVPNServerWorkMode::SERVER_ANTI_DPI_NODE, "Anti DPI server Mode"}, {QVPNServerWorkMode::SERVER_DPI_TERROR, "DPI Terror Mode"} };

			static inline std::unordered_map<std::string_view, QVPNServerWorkMode> server_modes_ = { {"QVPN Mode", QVPNServerWorkMode::SERVER_VPN,}, {"Proxy Mode", QVPNServerWorkMode::SERVER_PROXY_NODE},
				{"Anti DPI server Mode", QVPNServerWorkMode::SERVER_ANTI_DPI_NODE}, {"DPI Terror Mode", QVPNServerWorkMode::SERVER_DPI_TERROR} };

		public:

			static std::string_view get_client_mode_verbose(QVPNClientWorkMode mode);
			static std::string_view get_server_mode_verbose(QVPNServerWorkMode mode);

			static QVPNClientWorkMode get_client_mode_by_verbose(std::string_view mode);
			static QVPNServerWorkMode get_server_mode_by_verbose(std::string_view mode);
		};


		// only ip4 and ip6
		enum NetProtocol : BaseTypes::UByte
		{
			IPv4 = 4,
			IPv6 = 6,
			NET_UNDEFINED = 255
		};

		// only tcp and udp
		enum TransportProtocol : BaseTypes::UByte
		{
			TCP = 6,
			UDP = 17,
			TRANSPORT_UNDEFINED = 255,
		};

		template <class AddrType>
		concept is_addr =
			requires (AddrType addr) {

			typename AddrType::AddrBytes_t;
			typename AddrType::AddrInt_t;

			//{ AddrType::get_addr_family() } -> std::same_as<int>;
			{ addr.get_addr_family() } -> std::same_as<NetProtocol>;
			{ addr.to_bytes() } -> std::same_as<typename AddrType::AddrBytes_t>;
			{ addr.to_string() } -> std::same_as<std::string>;
			{ addr.to_uint() } -> std::same_as<typename AddrType::AddrInt_t>;

			{ addr.get_addr_size() } -> std::same_as<size_t>;

		};


		template <class ByteImpl>
		concept is_byte = std::is_same_v<ByteImpl, BaseTypes::UByte> || std::is_same_v<ByteImpl, BaseTypes::Byte> || std::is_same_v<ByteImpl, const BaseTypes::UByte> || std::is_same_v<ByteImpl, const BaseTypes::Byte>;

		class IPv4Address
		{

		public:

			using UByte = Core::BaseTypes::UByte;
			using AddrBytes_t = std::array<UByte, 4>;
			using AddrInt_t = BaseTypes::UInt;

		private:

			AddrBytes_t ip_{};

		public:
			// default construct is INADDR_ANY
			IPv4Address();

			template<std::random_access_iterator Iter>
			IPv4Address(Iter begin, Iter end)
			{
				std::copy(begin, end, ip_.begin());
			}

			IPv4Address(AddrBytes_t data);
			IPv4Address(std::string_view data);
			IPv4Address(std::initializer_list<UByte> list);
			IPv4Address(AddrInt_t data);
			IPv4Address(UByte first, UByte second, UByte third, UByte four);
			IPv4Address(const IPv4Address& other);
			IPv4Address(IPv4Address&& other);
			IPv4Address& operator=(const IPv4Address& other);
			IPv4Address& operator=(IPv4Address&& other);
			IPv4Address& operator=(const AddrBytes_t& other);
			IPv4Address& operator=(AddrBytes_t&& other);

			UByte operator[](int elem) const;

			bool operator==(const IPv4Address& other) const;

			//static consteval int get_addr_family();
			NetProtocol get_addr_family() const;
			size_t get_addr_size() const;

			AddrBytes_t to_bytes() const;
			std::string to_string() const;
			AddrInt_t to_uint() const;

			~IPv4Address();


		};


		class IPv6Address
		{
		public:

			using UByte = Core::BaseTypes::UByte;
			using AddrBytes_t = std::array<UByte, 16>;
			using AddrInt_t = std::array<UByte, 16>;

		private:

			AddrBytes_t ip_{};

		public:

			// default construct is IN6ADDR_ANY
			IPv6Address();

			template <std::random_access_iterator Iter>
			IPv6Address(Iter begin, Iter end)
			{
				std::copy(begin, end, ip_.begin());
			}

			IPv6Address(AddrBytes_t data);
			IPv6Address(std::initializer_list<UByte> list);
			IPv6Address(UByte data[16]);
			IPv6Address(std::string_view data);

			//static consteval int get_addr_family();
			NetProtocol get_addr_family() const;
			size_t get_addr_size() const;

			AddrBytes_t to_bytes() const;
			std::string to_string() const;
			AddrInt_t to_uint() const;
		};

		// no type addr
		class NetAddr
		{
		public:

			using UByte = Core::BaseTypes::UByte;
			using AddrBytes_t = std::vector<UByte>;
			using AddrInt_t = Core::BaseTypes::UInt;

		private:

			AddrBytes_t ip_{};

		public:
			// default construct is INADDR_ANY/IN6ADDR_ANY
			NetAddr();

			template <is_byte ... Byte>
			NetAddr(Byte&& ... bytes)
			{
				((ip_.push_back(bytes)), ...);
			}

			template <std::random_access_iterator Iter>
			NetAddr(Iter begin, Iter end)
			{
				std::copy(begin, end, std::back_inserter(ip_));
			}

			NetAddr(AddrBytes_t data);
			NetAddr(std::initializer_list<UByte> list);
			NetAddr(const IPv4Address& data);
			NetAddr(const IPv6Address& data);
			NetAddr(std::string_view data);

			size_t get_addr_size() const;
			NetProtocol get_addr_family() const;

			IPv4Address to_ipv4() const;
			IPv6Address to_ipv6() const;

			UByte operator[](int elem) const;

			AddrBytes_t to_bytes() const;
			std::string to_string() const;
			AddrInt_t to_uint() const;

			bool operator==(const NetAddr& other) const;
		};


		template <is_addr Addr>
		class UnifiedNetAddr : public Addr
		{
		public:

			std::shared_ptr<Addr> get_addr() const
			{
				return std::make_shared<Addr>(static_cast<Addr*>(this));
			}
		};
	}
}

// hash impl for whitelist
namespace std
{
	template<>
	struct hash<QVPN::Core::IPv4Address> {
		size_t operator()(const QVPN::Core::IPv4Address& obj) const {
			return hash<std::string>()(obj.to_string());
		}
	};

}


namespace QVPN {

	namespace Core {


		template <typename T>
		concept is_adapter_driver =
			requires(T t) {

			typename T::AdapterList_t;
			typename T::Adapter_t;
			typename T::AdapterHandle_t;

			{ t.create_adapter_ipv4() } -> std::same_as<void>;
			{ t.create_adapter_ipv4(std::declval<std::string_view>(), std::declval<std::string_view>(), std::declval<const QVPN::Core::IPv4Address&>()) } -> std::same_as<void>;
			{ t.get_ipv4_adapter() } -> std::same_as<std::shared_ptr<const typename T::Adapter_t>>;
			{ t.capture_adapter() } -> std::same_as<void>;
			{ t.close_adapter() } -> std::same_as<void>;
		};


		template <class T>
		concept is_net_driver =
			requires (T t) {

			typename T::Filter_t;

			{ t.init_driver(std::declval<const QVPN::Core::IPv4Address&>()) } -> std::same_as<void>;
			{ t.add_incoming_traffic_filter(std::declval<typename T::Filter_t>()) } -> std::same_as<void>;
			{ t.add_outgoing_traffic_filter(std::declval<typename T::Filter_t>()) } -> std::same_as<void>;
			{ t.start_capture_outgoing_traffic(std::declval<const QVPN::Core::IPv4Address&>(), std::declval<QVPN::Core::BaseTypes::ULong>()) } -> std::same_as<void>;
			{ t.start_capture_incoming_traffic(std::declval<const QVPN::Core::IPv4Address&>()) } -> std::same_as<void>;
			{ t.stop_capture_traffic() } -> std::same_as<void>;
		};


		template <class Filter>
		concept is_filter_type =
			requires (Filter f, typename Filter::Convertable_from c_f) {

			typename Filter::Convertable_to;
			typename Filter::Convertable_from;

			{ f.operator&&(std::declval<const Filter&>()) } -> std::same_as<Filter&>;
			{ f.operator||(std::declval<const Filter&>()) } -> std::same_as<Filter&>;
			{ f.operator!() } -> std::same_as<Filter&>;
			{ Filter(c_f) };
			{ f.operator Filter::Convertable_to() };
		};


		template <class Filter>
		concept is_filter =
			requires (Filter f) {

			typename Filter::Filter_t;

			{ f.ipv4() } -> std::same_as<typename Filter::Filter_t>;
			{ f.ipv6() } -> std::same_as<typename Filter::Filter_t>;
			{ f.tcp() } -> std::same_as<typename Filter::Filter_t>;
			{ f.udp() } -> std::same_as<typename Filter::Filter_t>;
			{ f.source(std::declval<const IPv4Address&>()) } -> std::same_as<typename Filter::Filter_t>;
			{ f.dest(std::declval<const IPv4Address&>()) } -> std::same_as<typename Filter::Filter_t>;
			{ f.tcp_src_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
			{ f.tcp_dst_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
			{ f.udp_src_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
			{ f.udp_dst_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
			{ f.src_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
			{ f.dst_port(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
			{ f.custom_protocol(std::declval<unsigned int>()) } -> std::same_as<typename Filter::Filter_t>;
			{ f.outgoing_traffic() } -> std::same_as<typename Filter::Filter_t>;
			{ f.incoming_traffic() } -> std::same_as<typename Filter::Filter_t>;
			{ f.local_traffic() } -> std::same_as<typename Filter::Filter_t>;
		};


		struct NetStatus
		{
			bool success;
			int status;
		};

		struct NetData
		{
			bool success;
			int status;
			NetAddr addr;
			BaseTypes::UShort port;
		};

		struct SocketRepairStatus
		{
			bool success;
			int status;
			std::string_view error_str;
		};

		template <class OStream>
		concept is_output_stream =
			requires (OStream os, std::string_view s) {
			os << s;
		};

		template <class FVPolicy, class OStream = std::stringstream>
		concept is_friendly_view_policy =
			requires (FVPolicy p, std::string_view v, OStream& os, std::string_view delim) {

			requires is_output_stream<OStream>;

				{ p.label(v, delim) } -> std::same_as<std::string>;
				{ p.label(os, v, delim) } -> std::same_as<void>;

				{ p.value(v, delim) } -> std::same_as<std::string>;
				{ p.value(os, v, delim) } -> std::same_as<void>;

				{ p.label_value(v, v, delim, delim) } -> std::same_as<std::string>;
				{ p.label_value(os, v, v, delim, delim) } -> std::same_as<void>;

		};


		enum class FriendlyViewPolicies : BaseTypes::UByte
		{
			FRIENDLY_VIEW_ONE_LINE = 0,
			FRIENDLY_VIEW_MULTIPLE_LINES = 1
		};


		template <FriendlyViewPolicies FVPolicy, is_output_stream OStream = std::stringstream>
		class FriendlyViewPolicy
		{
		public:

		};

		// one line spec
		template <is_output_stream OStream>
		class FriendlyViewPolicy<FriendlyViewPolicies::FRIENDLY_VIEW_ONE_LINE, OStream>
		{
		public:

			std::string label(std::string_view l, std::string_view delimiter = " ")
			{
				std::stringstream ss{};
				ss << l << ":" << delimiter;
				return ss.str();
			}

			void label(OStream& os, std::string_view l, std::string_view delimiter = " ")
			{
				os << l << ":" << delimiter;
			}

			std::string value(std::string_view v, std::string_view delimiter = " ")
			{
				std::stringstream ss{};
				ss << v << delimiter;
				return ss.str();
			}

			void value(OStream& os, std::string_view v, std::string_view delimiter = " ")
			{
				os << v << delimiter;
			}

			std::string label_value(std::string_view l, std::string_view v, std::string_view label_delimiter = " ", std::string_view value_delimiter = " ")
			{
				std::stringstream ss{};
				ss << l << ":" << label_delimiter << v << value_delimiter;
				return ss.str();
			}

			void label_value(OStream& os, std::string_view l, std::string_view v, std::string_view label_delimiter = " ", std::string_view value_delimiter = " ")
			{
				os << l << ":" << label_delimiter << v << value_delimiter;
			}

		};

		// multiple lines spec
		template <is_output_stream OStream>
		class FriendlyViewPolicy<FriendlyViewPolicies::FRIENDLY_VIEW_MULTIPLE_LINES, OStream>
		{
		public:

			std::string label(std::string_view l, std::string_view delimiter = " ")
			{
				std::stringstream ss{};
				ss << l << ":" << delimiter;
				return ss.str();
			}

			void label(OStream& os, std::string_view l, std::string_view delimiter = " ")
			{
				os << l << ":" << delimiter;
			}

			std::string value(std::string_view v, std::string_view delimiter = "")
			{
				std::stringstream ss{};
				ss << v << delimiter << std::endl;
				return ss.str();
			}

			void value(OStream& os, std::string_view v, std::string_view delimiter = "")
			{
				os << v << delimiter << std::endl;
			}

			std::string label_value(std::string_view l, std::string_view v, std::string_view label_delimiter = " ", std::string_view value_delimiter = "")
			{
				std::stringstream ss{};
				ss << l << ":" << label_delimiter << v << value_delimiter << std::endl;
				return ss.str();
			}

			void label_value(OStream& os, std::string_view l, std::string_view v, std::string_view label_delimiter = " ", std::string_view value_delimiter = "")
			{
				os << l << ":" << label_delimiter << v << value_delimiter << std::endl;
			}

		};


		struct QVPNServerSocketData
		{
			NetProtocol net_proto;
			TransportProtocol transport_proto;

			QVPN::Core::NetAddr client_local_addr;
			QVPN::Core::NetAddr server_local_addr;
			BaseTypes::UShort local_port;

			QVPN::Core::NetAddr remote_addr;
			BaseTypes::UShort remote_port;


			std::string to_string() const;

			// для std::unordered_map
			bool operator==(const QVPNServerSocketData& other) const
			{
				return net_proto == other.net_proto &&
					transport_proto == other.transport_proto &&
					client_local_addr == other.client_local_addr &&
					server_local_addr == other.server_local_addr &&
					local_port == other.local_port &&
					remote_addr == other.remote_addr &&
					remote_port == other.remote_port;
			}

			template <is_friendly_view_policy FVPolicy = FriendlyViewPolicy<FriendlyViewPolicies::FRIENDLY_VIEW_ONE_LINE>>
			std::string to_friendly_view(FVPolicy p = FriendlyViewPolicy<FriendlyViewPolicies::FRIENDLY_VIEW_ONE_LINE>{}) const
			{
				std::stringstream ss{};

				auto ip_str = std::to_string(static_cast<BaseTypes::UInt>(net_proto));
				auto proto_str = std::to_string(static_cast<BaseTypes::UInt>(transport_proto));
				p.label_value(ss, "IP", ip_str);
				p.label_value(ss, "TProto", proto_str);

				auto local_str = std::format("{}:{}", client_local_addr.to_string(), local_port);
				p.label_value(ss, "Client local socket data", local_str);
				auto local_str1 = std::format("{}:{}", server_local_addr.to_string(), local_port);
				p.label_value(ss, "Server local socket data", local_str1);
				auto remote_str = std::format("{}:{}", remote_addr.to_string(), remote_port);
				p.label_value(ss, "Remote socket data", remote_str);
				return ss.str();
			}
		};


		struct QVPNSocketData
		{
			NetProtocol net_proto;
			TransportProtocol transport_proto;

			QVPN::Core::NetAddr local_addr;
			BaseTypes::UShort local_port;

			QVPN::Core::NetAddr remote_addr;
			BaseTypes::UShort remote_port;

			std::string to_string() const;

			// для std::unordered_map
			bool operator==(const QVPNSocketData& other) const
			{
				return net_proto == other.net_proto && 
					transport_proto == other.transport_proto &&
					local_addr == other.local_addr &&
					local_port == other.local_port &&
					remote_addr == other.remote_addr &&
					remote_port == other.remote_port;
			}

			template <is_friendly_view_policy FVPolicy = FriendlyViewPolicy<FriendlyViewPolicies::FRIENDLY_VIEW_ONE_LINE>>
			std::string to_friendly_view(FVPolicy p = FriendlyViewPolicy<FriendlyViewPolicies::FRIENDLY_VIEW_ONE_LINE>{}) const
			{
				std::stringstream ss{};

				auto ip_str = std::to_string(static_cast<BaseTypes::UInt>(net_proto));
				auto proto_str = std::to_string(static_cast<BaseTypes::UInt>(transport_proto));
				p.label_value(ss, "IP", ip_str);
				p.label_value(ss, "TProto", proto_str);

				auto local_str = std::format("{}:{}", local_addr.to_string(), local_port);
				p.label_value(ss, "Local socket data", local_str);
				auto remote_str = std::format("{}:{}", remote_addr.to_string(), remote_port);
				p.label_value(ss, "Remote socket data", remote_str);
				return ss.str();
			}
		};


		class QVPNSocketSettings
		{
			bool ip_header_ = false;
			int recv_timeout_ = 0;

		public:
			QVPNSocketSettings(bool ip_data = false, int receive_timeout_ms = 0);
			bool ip_header() const;
			int receive_timeout_ms() const;
		};


		struct ReceiveData
		{
			static constexpr BaseTypes::UInt buffer_size = 1 << 16;

			NetStatus status;
			BaseTypes::Long size;
			std::array<BaseTypes::UByte, buffer_size> data;
		};


		enum class BytesParseSignal
		{
			BP_FULL_OBJECT = 0,
			BP_NOT_FULL_OBJECT = 1,
			BP_FULL_OBJECT_AND_TAIL = 2,
			BP_NO_DATA = 3,
			BP_ERROR = 99
		};

		struct ProtoTemplateParseResult
		{
			BaseTypes::UByte* begin = nullptr; // object start
			BaseTypes::UByte* end = nullptr; // object end

			BytesParseSignal bp_signal = BytesParseSignal::BP_NO_DATA; // info signal
			BaseTypes::UByte* real_end = nullptr; // real size of input data
		};


		template <class ProtoTemplate>
		concept is_proto_template =
			requires (ProtoTemplate t, BaseTypes::UByte * b, BaseTypes::UByte * e) {

			ProtoTemplate{ b, e }; // constructable from (b, e)

			{ ProtoTemplate::bytes_parse(b, e) } -> std::same_as<ProtoTemplateParseResult>;
		};


		namespace details
		{
			using UByte = QVPN::Core::BaseTypes::UByte;

			class DummyNetLevelProtoTemplate
			{
			public:
				DummyNetLevelProtoTemplate(UByte* begin, UByte* end) {}

				static inline ProtoTemplateParseResult bytes_parse(UByte* begin, UByte* end) { return ProtoTemplateParseResult{}; };
			};


			class DummyTransportLevelProtoTemplate
			{
				public:
				DummyTransportLevelProtoTemplate(UByte* begin, UByte* end) {}

				static inline ProtoTemplateParseResult bytes_parse(UByte* begin, UByte* end) { return ProtoTemplateParseResult{}; };
			};


			class DummyAppLevelProtoTemplate
			{
			public:

				DummyAppLevelProtoTemplate(UByte* begin, UByte* end) {}

				static inline ProtoTemplateParseResult bytes_parse(UByte* begin, UByte* end) { return ProtoTemplateParseResult{}; };

			};
		};


		enum class SafeReceiveSignal
		{
			SFR_FULL_DATA = 0,
			SFR_WAIT_DATA = 1,
			SFR_NO_DATA = 2,
			SFR_ERROR = 99
		};

		template <class SafeReceiveDataType>
		concept is_safe_receive_data =
			requires (SafeReceiveDataType sfr, const SafeReceiveDataType csfr, SafeReceiveSignal signal, BaseTypes::UByte * b, BaseTypes::UByte * e, size_t i, const NetStatus& status) {

			typename SafeReceiveDataType::AppLevelProtoTemplateType;

			{ sfr.add_objects_and_validate(signal, b, e) } -> std::same_as<SafeReceiveSignal>;

			{ csfr.get_status() } -> std::same_as<NetStatus>;

			{ csfr.get_object_bytes(i) } -> std::same_as<std::pair<const BaseTypes::UByte*, const BaseTypes::UByte*>>;
			{ sfr.get_object_bytes(i) } -> std::same_as<std::pair<BaseTypes::UByte*, BaseTypes::UByte*>>;

			{ csfr.get_objects_num() } -> std::same_as<BaseTypes::UInt>;

			{ csfr.get_object(i) } -> std::same_as<typename SafeReceiveDataType::AppLevelProtoTemplateType>;

			{ csfr.to_bytes() } -> std::same_as<std::pair<const BaseTypes::UByte*, const BaseTypes::UByte*>>;
			{ sfr.to_bytes() } -> std::same_as<std::pair<BaseTypes::UByte*, BaseTypes::UByte*>>;

			{ sfr.set_status(status) } -> std::same_as<void>;

		};


		template <is_proto_template AppLevelProtoTemplate>
		struct SafeReceiveData
		{
			using UByte = BaseTypes::UByte;
			using UInt = BaseTypes::UInt;
			using SeparatorType = std::pair<size_t, size_t>;
			using AppLevelProtoTemplateType = AppLevelProtoTemplate;
			using BytesParseSignal = QVPN::Core::BytesParseSignal;

			NetStatus status{};
			std::vector<SeparatorType> separators;
			std::vector<UByte> data{};

			using DataIterator_t = UByte*;
			using ConstDataIterator_t = const UByte*;

		private:

			ProtoTemplateParseResult parse_object(BaseTypes::UByte* begin, BaseTypes::UByte* end) const
			{
				return AppLevelProtoTemplate::bytes_parse(begin, end);
			}

			size_t get_last_object()
			{
				if (separators.size() == 0)
					separators.emplace_back(0, 0);
				auto last = separators.size() - 1;
				return last;
			}

			// add full object
			void _add_object(UByte* begin, UByte* end)
			{
				data.insert(data.end(), begin, end);
				auto start = data.size() - std::distance(begin, end);
				auto fin = data.size();
				separators.emplace_back(start, fin);
			}

			// add data to not full object
			void _add_data_to_object(UByte* begin, UByte* end)
			{
				auto last = get_last_object();
				auto start = separators[last].first;
				data.insert(data.end(), begin, end);
				auto fin = data.size();
				separators[last].second = fin;
			}

			// basic parse no cycle
			SafeReceiveSignal parse_data(BaseTypes::UByte* begin, BaseTypes::UByte* end)
			{
				auto parse_res = parse_object(begin, end);
				switch (parse_res.bp_signal)
				{
				case BytesParseSignal::BP_FULL_OBJECT:
					_add_object(parse_res.begin, parse_res.end);
					return SafeReceiveSignal::SFR_FULL_DATA;
					break;
				case BytesParseSignal::BP_NOT_FULL_OBJECT:
					_add_object(parse_res.begin, parse_res.real_end);
					return SafeReceiveSignal::SFR_WAIT_DATA;
					break;
				case BytesParseSignal::BP_FULL_OBJECT_AND_TAIL:
					_add_object(parse_res.begin, parse_res.end);
					_add_object(parse_res.end, parse_res.real_end);
					return SafeReceiveSignal::SFR_WAIT_DATA;
					break;
				default:
					return SafeReceiveSignal::SFR_ERROR;
					break;
				}
			}

			// add data to object and parse with existing data
			SafeReceiveSignal _add_data_and_parse(UByte* begin, UByte* end)
			{
				auto last = get_last_object();
				auto start = separators[last].first;

				data.insert(data.end(), begin, end); // raw add

				auto fin = data.size();
				separators[last].second = fin;

				while (true)
				{
					auto parse_res = parse_object(data.data() + start, data.data() + fin);
					switch (parse_res.bp_signal)
					{
					case BytesParseSignal::BP_FULL_OBJECT:
						return SafeReceiveSignal::SFR_FULL_DATA;
						break;
					case BytesParseSignal::BP_NOT_FULL_OBJECT:
						return SafeReceiveSignal::SFR_WAIT_DATA;
						break;
					case BytesParseSignal::BP_FULL_OBJECT_AND_TAIL:
					{
						auto size = std::distance(parse_res.begin, parse_res.end); // size of object
						auto tail_size = std::distance(parse_res.end, parse_res.real_end); // tail size
						auto tail_start = separators[last].second; // tail start
						separators[last].second = separators[last].first + size; // cut tail from full object
						separators.emplace_back(tail_start, tail_start + tail_size); // add tail separator
						start = tail_start;
						fin = start + tail_size;
						break;
					}
					default:
						return SafeReceiveSignal::SFR_ERROR;
						break;
					}
				}
			}

		public:

			SafeReceiveSignal add_objects_and_validate(SafeReceiveSignal prev_signal, BaseTypes::UByte* begin, BaseTypes::UByte* end)
			{
				if (prev_signal == SafeReceiveSignal::SFR_WAIT_DATA) // if have not full object from prev calls
				{
					return _add_data_and_parse(begin, end);
				}

				return parse_data(begin, end); // for first call
			}

			NetStatus get_status() const
			{
				return status;
			}

			void set_status(const NetStatus& net_status)
			{
				status.status = net_status.status;
				status.success = net_status.success;
			}

			std::pair<ConstDataIterator_t, ConstDataIterator_t> get_object_bytes(size_t i) const
			{
				auto [b, e] = separators[i];
				return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data.data() + b, data.data() + e);
			}

			std::pair<DataIterator_t, DataIterator_t> get_object_bytes(size_t i)
			{
				auto [b, e] = separators[i];
				return std::pair<DataIterator_t, DataIterator_t>(data.data() + b, data.data() + e);
			}

			UInt get_objects_num() const
			{
				return separators.size();
			}

			AppLevelProtoTemplate get_object(size_t i) const
			{
				auto [b, e] = separators[i];
				return AppLevelProtoTemplate(b, e);
			}

			std::pair<ConstDataIterator_t, ConstDataIterator_t> to_bytes() const
			{
				return std::pair<ConstDataIterator_t, ConstDataIterator_t>(data.data(), data.data() + data.size());
			}

			std::pair<DataIterator_t, DataIterator_t> to_bytes()
			{
				return std::pair<DataIterator_t, DataIterator_t>(data.data(), data.data() + data.size());
			}

		};



		template <class SockFilter>
		concept is_socket_filter =
			requires (SockFilter sf, const NetAddr& addr, QVPN::Core::BaseTypes::UShort port, BaseTypes::UByte proto, BaseTypes::UByte net, const SockFilter& csf_ref, const QVPNSocketData& csd_r, const QVPNServerSocketData& cssd_r) {

			typename SockFilter::SocketFilter_t;

			SockFilter{ csd_r };
			SockFilter{ cssd_r };

				{ sf.net_ver(net) } -> std::same_as<void>;
				{ sf.ipv4() } -> std::same_as<void>;
				{ sf.ipv6() } -> std::same_as<void>;

				{ sf.src(addr) } -> std::same_as<void>;
				{ sf.dst(addr) } -> std::same_as<void>;
				{ sf.src_port(port) } -> std::same_as<void>;
				{ sf.dst_port(port) } -> std::same_as<void>;
				{ sf.custom_protocol(proto) } -> std::same_as<void>;
				{ sf.tcp() } -> std::same_as<void>;
				{ sf.udp() } -> std::same_as<void>;

				{ sf.get_filters() } -> std::same_as<typename SockFilter::SocketFilter_t&>;

		};


		template <class SocketImpl, class Addr>
		concept is_socket =
			requires (SocketImpl t, const BaseTypes::UByte * begin, const BaseTypes::UByte * end, const Addr & addr, const BaseTypes::UShort port, int flags, int con_limit, 
		const QVPNSocketSettings & sock_settings, BaseTypes::UInt arg, const QVPNSocketData& sock_data) {

			SocketImpl::buffer_size;

			{ t.reconnect(addr, port) } -> std::same_as<NetStatus>;
			{ t.connect(addr, port) } -> std::same_as<NetStatus>;
			{ t.disconnect() } -> std::same_as<NetStatus>;
			{ t.close_socket() } -> std::same_as<void>;
			{ t.disconnect_if_connected() } -> std::same_as<void>;

			{ t.bind(addr, port) } -> std::same_as<NetStatus>;
			{ t.listen(con_limit) } -> std::same_as<NetStatus>;
			{ t. template accept<Addr>() } -> std::same_as<SocketImpl>;

			{ t.send(begin, end, flags) } -> std::same_as<NetStatus>;
			{ t.receive(flags) } -> std::same_as<ReceiveData>;

			{ t.get_local_addr() } -> std::same_as<const Addr&>;
			{ t.get_local_port() } -> std::same_as<BaseTypes::UShort>;

			{ t.get_remote_addr() } -> std::same_as<const Addr&>;
			{ t.get_remote_port() } -> std::same_as<BaseTypes::UShort>;

			{ t.get_transport_protocol() } -> std::same_as<TransportProtocol>;

			{ t.apply_settings(sock_settings) } -> std::same_as<void>;

			{ t.template send_to<Addr>(addr, port, begin, end) } -> std::same_as<NetStatus>;
			{ t.template recv_from<Addr>(addr, port) } -> std::same_as<ReceiveData>;

			{ t.template safe_recv<details::DummyAppLevelProtoTemplate>(flags) } -> is_safe_receive_data;

			{ t.is_valid() } -> std::same_as<bool>;
			{ t.get_socket_data() } -> std::same_as<const QVPNSocketData&>;

			{ t.append_socket_to_connection(sock_data, arg, arg) } -> std::same_as<SocketRepairStatus>;
		};

		template <class SocketImpl, class Addr, class SockFilter>
		concept is_raw_socket =
			requires (SocketImpl t, const BaseTypes::UByte * begin, const BaseTypes::UByte * end, const Addr & addr, const BaseTypes::UShort port, int flags, int con_limit, const QVPNSocketSettings & sock_settings, SockFilter& csf) {

			requires is_socket_filter<SockFilter>;

			SocketImpl::buffer_size;
			typename SocketImpl::SocketFilter;

			{ t.reconnect(addr, port) } -> std::same_as<NetStatus>;
			{ t.connect(addr, port) } -> std::same_as<NetStatus>;
			{ t.disconnect() } -> std::same_as<NetStatus>;
			{ t.close_socket() } -> std::same_as<void>;
			{ t.disconnect_if_connected() } -> std::same_as<void>;

			{ t.bind(addr, port) } -> std::same_as<NetStatus>;
			{ t.listen(con_limit) } -> std::same_as<NetStatus>;
			{ t. template accept<Addr>() } -> std::same_as<SocketImpl>;

			{ t.send(begin, end, flags) } -> std::same_as<NetStatus>;
			{ t.receive(flags) } -> std::same_as<ReceiveData>;

			{ t.get_local_addr() } -> std::same_as<const Addr&>;
			{ t.get_local_port() } -> std::same_as<BaseTypes::UShort>;

			{ t.get_remote_addr() } -> std::same_as<const Addr&>;
			{ t.get_remote_port() } -> std::same_as<BaseTypes::UShort>;

			{ t.get_transport_protocol() } -> std::same_as<TransportProtocol>;

			{ t.apply_settings(sock_settings) } -> std::same_as<void>;

			{ t.template send_to<Addr>(addr, port, begin, end) } -> std::same_as<NetStatus>;
			{ t.template recv_from<Addr>(addr, port) } -> std::same_as<ReceiveData>;

			{ t.template safe_recv<details::DummyNetLevelProtoTemplate, details::DummyTransportLevelProtoTemplate, details::DummyAppLevelProtoTemplate>(flags) } -> is_safe_receive_data;

			{ t.is_valid() } -> std::same_as<bool>;
			{ t.get_socket_data() } -> std::same_as<const QVPNSocketData&>;

			{ t.filter(csf) } -> std::same_as<void>;
		};


		template <class NetToolsImpl>
		concept is_net_tools =
			requires (NetToolsImpl t, NetProtocol net_proto, TransportProtocol t_proto, BaseTypes::UShort us, BaseTypes::UInt ui, BaseTypes::ULong ul, const QVPNSocketData& csd_r) {

			typename NetToolsImpl::Socket;
			typename NetToolsImpl::RawSocket;
			typename NetToolsImpl::SocketFilter;

				{ NetToolsImpl::create_socket(net_proto, t_proto) } -> std::same_as<typename NetToolsImpl::Socket>;
				{ NetToolsImpl::create_raw_socket(net_proto, t_proto) } -> std::same_as<typename NetToolsImpl::RawSocket>;
				{ NetToolsImpl::create_socket_filter(csd_r) } -> std::same_as<typename NetToolsImpl::SocketFilter>;

				{ NetToolsImpl::hton(us) } -> std::same_as<BaseTypes::UShort>;
				{ NetToolsImpl::hton(ui) } -> std::same_as<BaseTypes::UInt>;
				{ NetToolsImpl::hton(ul) } -> std::same_as<BaseTypes::ULong>;

				{ NetToolsImpl::ntoh(us) } -> std::same_as<BaseTypes::UShort>;
				{ NetToolsImpl::ntoh(ui) } -> std::same_as<BaseTypes::UInt>;
				{ NetToolsImpl::ntoh(ul) } -> std::same_as<BaseTypes::ULong>;
		};


		template <typename T>
		concept is_net_number = std::integral<T> || std::floating_point<T>;

		template <class PreParserImpl>
		concept is_preparser =
			requires (PreParserImpl pp) {

			typename PreParserImpl::FullPacketType;
			typename PreParserImpl::NoNetPacketType;

			{ pp.pre_parse() }; //TODO: Как сюда засунуть шаблонный параметр?

		};

		template <class PacketBuilderDataImpl>
		concept PacketBuilderDataLike =
			requires (PacketBuilderDataImpl p) {

				{ p.get_packet_id() } -> std::same_as<BaseTypes::UByte>;
				{ p.get_offset() } -> std::same_as<BaseTypes::UShort>;
				{ p.get_original_size() } -> std::same_as<BaseTypes::UShort>;

		};

		template <class AdapterDriverImpl>
			requires is_adapter_driver<AdapterDriverImpl>
		class AdapterDriver final : public AdapterDriverImpl
		{


		};


		template <class NetDriverImpl>
			requires is_net_driver<NetDriverImpl>
		class NetDriver final : public NetDriverImpl
		{

		};



		template <class FilterImpl>
			requires is_filter<FilterImpl>
		class TrafficFilter_ final : public FilterImpl
		{

		};


		class QVPNWhitelistElement
		{
		public:
			static constexpr int default_priority = 1;

		private:
			std::string host_;
			int priority_;

		public:
			QVPNWhitelistElement();
			QVPNWhitelistElement(std::string_view host, int priority = QVPNWhitelistElement::default_priority);

			void set_host(std::string_view host);
			void set_priority(int priority);

			std::string_view get_host() const;
			int get_priority() const;
		};


		class QVPNWhitelistElementView
		{
		private:
			std::string_view host_;
			int priority_;

		public:
			QVPNWhitelistElementView(const QVPNWhitelistElement& elem);

			std::string_view get_host() const;
			int get_priority() const;
		};


		template <class WhitelistStrategyImpl, class ... Args>
		concept is_whitelist_strategy =
			requires (WhitelistStrategyImpl t, const Args&& ... args) {

				{ WhitelistStrategyImpl() };
				{ t.get_host_by_params(args...) } -> std::same_as<QVPNWhitelistElementView>;

		};

		template <class WhitelistImpl, class WhitelistStrategy, class ... Args>
		concept is_whitelist =
			requires (WhitelistImpl t, size_t i, WhitelistStrategy & strategy, const Args&& ... args) {

				{ t.get_random_host() } -> std::same_as<std::string_view>;
				{ t.get_host(i) } -> std::same_as<std::string_view>;
				{ t.get_size() } -> std::same_as<size_t>;
				{ t.get_by_strategy(strategy, args...) } -> std::same_as<std::string_view>;
		};


		template <class Data>
		concept is_whitelist_data = std::convertible_to<Data, std::string_view> || std::convertible_to<Data, std::string>;

		class QVPNWhitelistDefaultStrategy
		{
		public:

			using StrategyFilter = IPv4Address;

		private:
			std::unordered_map<StrategyFilter, QVPNWhitelistElement> map_;

		public:
			QVPNWhitelistDefaultStrategy();

			QVPNWhitelistElementView get_host_by_params(const StrategyFilter& param);
		};

		class QVPNWhitelist
		{
		private:
			std::vector<QVPNWhitelistElement> whitelist_;

		public:
			QVPNWhitelist();
			QVPNWhitelist(std::string_view path);

			void parse_whitelist(std::string_view path);

			std::string_view get_random_host() const;
			std::string_view get_host(size_t i) const;
			size_t get_size() const;

			template <class Strategy, class ... Args>
				requires is_whitelist_strategy<Strategy, Args...>
			std::string_view get_by_strategy(Strategy& strategy, const Args&& ... args) const
			{
				auto elem = strategy.get_host_by_params(std::forward<const Args>(args)...);
				return elem.get_host();
			}
		};


		enum TCPFlags : BaseTypes::UShort
		{
			FIN = 0x01,
			SYN = 0x02,
			RST = 0x04,
			PSH = 0x08,
			ACK = 0x10,
			URG = 0x20,
			ECE = 0x40,
			CWR = 0x80,
			NS = 0x100,

			// helpers
			SYN_ACK = 0x12,
		};


		class TcpFlagsObject
		{
		public:
			using UByte = BaseTypes::UByte;
			using UShort = BaseTypes::UShort;

		private:
			UShort flags_ = 0;

		public:

			TcpFlagsObject(UShort flags);
			TcpFlagsObject(UByte ns, UByte cwr, UByte ecn, UByte urg, UByte ack, UByte psh, UByte rst, UByte syn, UByte fin);

			UByte get_ns() const;
			UByte get_cwr() const;
			UByte get_ecn() const;
			UByte get_urg() const;
			UByte get_ack() const;
			UByte get_psh() const;
			UByte get_rst() const;
			UByte get_syn() const;
			UByte get_fin() const;

			UByte get_without_ns() const;

			// to short, from shosrt
			operator UShort() const;
			UByte operator[](size_t i) const;
		};


		class QVPNVerboser
		{
		private:

			static inline std::unordered_map<NetProtocol, std::string> net_verbose_ = { { NetProtocol::IPv4, "IPv4"}, { NetProtocol::IPv6, "IPv6"} };
			static inline std::unordered_map<TransportProtocol, std::string> transport_verbose_ = { { TransportProtocol::TCP, "TCP"}, { TransportProtocol::UDP, "UDP"} };
			static inline std::array<std::string_view, 9> tcp_flags_ = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", "NS"};
			

		public:

			static std::string_view net_verbose(NetProtocol net);
			static void register_net_verbose(NetProtocol net, std::string_view verbose);

			static std::string_view transport_verbose(TransportProtocol transport);
			static void register_transport_verbose(TransportProtocol transport, std::string_view verbose);
			
			static std::string tcp_flags(TcpFlagsObject flags);

		};


	}

}

// for server driver
namespace std
{
	template<>
	struct hash<QVPN::Core::QVPNSocketData> {

		size_t operator()(const QVPN::Core::QVPNSocketData& data) const {
			return hash<std::string>()(data.to_string());
		}

	};

	template<>
	struct hash<QVPN::Core::QVPNServerSocketData> {

		size_t operator()(const QVPN::Core::QVPNServerSocketData& data) const {
			return hash<std::string>()(data.to_string());
		}

	};

}