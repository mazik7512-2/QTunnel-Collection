#pragma once

#include <qvpn_general.hpp>
#include <array>


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


		template <class AddrType>
		concept is_addr =
			requires (AddrType addr) {

			typename AddrType::AddrBytes_t;
			typename AddrType::AddrInt_t;

			//{ AddrType::get_addr_family() } -> std::same_as<int>;
			{ addr.get_addr_family() } -> std::same_as<int>;
			{ addr.to_bytes() } -> std::same_as<typename AddrType::AddrBytes_t>;
			{ addr.to_string() } -> std::same_as<std::string>;
			{ addr.to_uint() } -> std::same_as<typename AddrType::AddrInt_t>;

		};


		template <class ByteImpl>
		concept is_byte = std::is_same_v<ByteImpl, BaseTypes::UByte> || std::is_same_v<ByteImpl, BaseTypes::Byte> || std::is_same_v<ByteImpl, const BaseTypes::UByte> || std::is_same_v<ByteImpl, const BaseTypes::Byte>;

		class NetAddr
		{
		public:

			using UByte = Core::BaseTypes::UByte;
			using AddrBytes_t = std::vector<UByte>;
			using AddrInt_t = std::pair<BaseTypes::ULong, BaseTypes::ULong>;

		private:

			AddrBytes_t addr_;

		public:
			
			NetAddr() = default;

			template <is_byte ... Byte>
			NetAddr(Byte&& ... bytes)
			{
				((addr_.push_back(bytes)), ...);
			}

			UByte operator[](int elem) const;

			consteval int get_addr_family();

			AddrBytes_t to_bytes() const;
			std::string to_string() const;
			AddrInt_t to_uint() const;
		};


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
			IPv4Address(AddrInt_t data);
			IPv4Address(UByte first, UByte second, UByte third, UByte four);
			IPv4Address(const IPv4Address& other);
			IPv4Address(IPv4Address&& other);
			IPv4Address& operator=(const IPv4Address& other);
			IPv4Address& operator=(IPv4Address&& other);
			IPv4Address& operator=(const AddrBytes_t& other);
			IPv4Address& operator=(AddrBytes_t&& other);

			UByte operator[](int elem) const;

			//static consteval int get_addr_family();
			consteval int get_addr_family();

			AddrBytes_t to_bytes() const;
			std::string to_string() const;
			AddrInt_t to_uint() const;

			~IPv4Address();


		};


		class Ipv6Address
		{
		public:

			using UByte = Core::BaseTypes::UByte;
			using AddrBytes_t = std::array<UByte, 16>;
			using AddrInt_t = std::array<UByte, 16>;

		private:

			AddrBytes_t ip_{};

		public:

			//static consteval int get_addr_family();
			consteval int get_addr_family();

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
			requires (SocketImpl t, const BaseTypes::UByte* begin, const BaseTypes::UByte* end, const UnifiedNetAddr<Addr>& addr, const BaseTypes::UShort port, int flags) {

			SocketImpl::buffer_size;

				{ t.connect(addr, port) } -> std::same_as<NetStatus>;
				{ t.disconnect() } -> std::same_as<NetStatus>;

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



}

}
