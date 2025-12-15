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


		// only ip4 and ip6
		enum NetProtocols : BaseTypes::UByte
		{
			IPv4 = 4,
			IPv6 = 6,
			UNDEFINED = 255
		};

		// only tcp and udp
		enum TransportProtocols : BaseTypes::UByte
		{
			TCP = 6,
			UDP = 17
		};

		template <class AddrType>
		concept is_addr =
			requires (AddrType addr) {

			typename AddrType::AddrBytes_t;
			typename AddrType::AddrInt_t;

			//{ AddrType::get_addr_family() } -> std::same_as<int>;
			{ addr.get_addr_family() } -> std::same_as<NetProtocols>;
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
			consteval NetProtocols get_addr_family();
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
			consteval NetProtocols get_addr_family();
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
			using AddrInt_t = std::vector<UByte>;

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

			size_t get_addr_size();
			NetProtocols get_addr_family() const;

			IPv4Address to_ipv4() const;
			IPv6Address to_ipv6() const;

			UByte operator[](int elem) const;

			AddrBytes_t to_bytes() const;
			std::string to_string() const;
			AddrInt_t to_uint() const;
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
			// Комбинируйте хэши полей
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


		template <class SocketImpl, class Addr>
		concept is_socket =
			requires (SocketImpl t, const BaseTypes::UByte * begin, const BaseTypes::UByte * end, const Addr &addr, const BaseTypes::UShort port, int flags, int con_limit) {

			SocketImpl::buffer_size;

			{ t.connect(addr, port) } -> std::same_as<NetStatus>;
			{ t.disconnect() } -> std::same_as<NetStatus>;

			{ t.bind(addr, port) } -> std::same_as<NetStatus>;
			{ t.listen(con_limit) } -> std::same_as<NetStatus>;
			{ t. template accept<Addr>() } -> std::same_as<SocketImpl>;

			{ t.send(begin, end, flags) } -> std::same_as<NetStatus>;
			{ t.receive(flags) } -> std::same_as<std::array<BaseTypes::UByte, SocketImpl::buffer_size>>;
		};


		template <class NetToolsImpl, class Socket>
		concept is_net_tools =
			requires (NetToolsImpl t, int socket_family, int socket_type, int proto) {

				{ NetToolsImpl::create_socket(socket_family, socket_type, proto) } -> std::same_as<Socket>;

		};

		template <class PreParserImpl>
		concept is_preparser =
			requires (PreParserImpl pp) {
				
			typename PreParserImpl::PacketType;

				{ pp.pre_parse() };

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

