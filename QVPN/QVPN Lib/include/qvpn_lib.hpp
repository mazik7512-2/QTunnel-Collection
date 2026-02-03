#pragma once
#include <qvpn_general.hpp>
#include <array>
#include <unordered_map>
#include <iterator>


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


		template <class LoggerImpl>
		concept is_logger = 
			requires (LoggerImpl l, std::string_view data) {

				{ l.info(data) } -> std::same_as<void>;
				{ l.success(data) } -> std::same_as<void>;
				{ l.fail(data) } -> std::same_as<void>;
				{ l.warning(data) } -> std::same_as<void>;

				{ l.set_prefix(data) } -> std::same_as<void>;
				{ l.clear_prefix() } -> std::same_as<void>;
		};


		enum class QVPNPlatform
		{
			WINDOWS = 0,
			LINUX = 1,
			ANDROID = 2,
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
			consteval NetProtocol get_addr_family();
			consteval size_t get_addr_size();

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
			consteval NetProtocol get_addr_family();
			consteval size_t get_addr_size();

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


		struct QVPNSocketData
		{
			TransportProtocol transport_proto;

			QVPN::Core::NetAddr local_addr;
			BaseTypes::UShort local_port;

			QVPN::Core::NetAddr remote_addr;
			BaseTypes::UShort remote_port;

			std::string to_string() const;

			// для std::unordered_map
			bool operator==(const QVPNSocketData& other) const
			{
				return transport_proto == other.transport_proto &&
					local_addr == other.local_addr &&
					local_port == other.local_port &&
					remote_addr == other.remote_addr &&
					remote_port == other.remote_port;
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
			int size;
			std::array<BaseTypes::UByte, buffer_size> data;
		};

		template <class SocketImpl, class Addr>
		concept is_socket =
			requires (SocketImpl t, const BaseTypes::UByte * begin, const BaseTypes::UByte * end, const Addr &addr, const BaseTypes::UShort port, int flags, int con_limit, const QVPNSocketSettings& sock_settings) {

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

			{ t.send_to(addr, port, begin, end) } -> std::same_as<NetStatus>;
			{ t.recv_from(addr, port) } -> std::same_as<ReceiveData>;
		};


		template <class NetToolsImpl, class Socket>
		concept is_net_tools =
			requires (NetToolsImpl t, NetProtocol net_proto, TransportProtocol t_proto) {

				{ NetToolsImpl::create_socket(net_proto, t_proto) } -> std::same_as<Socket>;
				{ NetToolsImpl::create_raw_socket(net_proto, t_proto) } -> std::same_as<Socket>;

		};

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
}