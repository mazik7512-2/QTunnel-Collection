#include <windivert.h>
#include <string_view>
#include <string>
#include "lib.hpp"

#pragma comment(lib, "windivert.lib")

namespace QVPN {

	namespace WinDivertExt {


		class WinDivertTrafficFilterType
		{
		private:
			std::string filter_;

		public:

			using Convertable_to = std::string_view;
			using Convertable_from = std::string_view;

			WinDivertTrafficFilterType() = delete;
			WinDivertTrafficFilterType(Convertable_from filter);
			
			WinDivertTrafficFilterType(const WinDivertTrafficFilterType& filter);
			WinDivertTrafficFilterType(WinDivertTrafficFilterType&& filter) noexcept;

			WinDivertTrafficFilterType& operator=(const WinDivertTrafficFilterType& filter);
			WinDivertTrafficFilterType& operator=(WinDivertTrafficFilterType&& filter) noexcept;
			
			WinDivertTrafficFilterType& operator&&(const WinDivertTrafficFilterType& t);
			
			operator Convertable_to() const;

		};

		template <class FilterType>
			requires QVPN::Core::is_filter_type<FilterType>
		class WinDivertTrafficFilter_
		{
		public:
			using Filter_t = FilterType;

			Filter_t ipv4() const noexcept
			{
				return Filter_t("ip");
			}

			Filter_t ipv6() const noexcept
			{
				return Filter_t("ipv6");
			}

			Filter_t tcp() const noexcept
			{
				return Filter_t("tcp");
			}

			Filter_t udp() const noexcept
			{
				return Filter_t("udp");
			}

			Filter_t source(const QVPN::Core::IPv4Address& addr) const noexcept
			{
				return Filter_t("localAddr == " + addr.to_string());
			}

			Filter_t dest(const QVPN::Core::IPv4Address& addr) const noexcept
			{
				return Filter_t("remoteAddr == " + addr.to_string());
			}

			Filter_t src_port(unsigned int port) const noexcept
			{
				return Filter_t("localPort == " + std::to_string(port));
			}

			Filter_t dst_port(unsigned int port) const noexcept
			{
				return Filter_t("remotePort == " + std::to_string(port));
			}

			Filter_t tcp_src_port(unsigned int port) const noexcept
			{
				return Filter_t("tcp.SrcPort == " + std::to_string(port));
			}

			Filter_t tcp_dst_port(unsigned int port) const noexcept
			{
				return Filter_t("tcp.DstPort == " + std::to_string(port));
			}

			Filter_t udp_src_port(unsigned int port) const noexcept
			{
				return Filter_t("udp.SrcPort == " + std::to_string(port));
			}

			Filter_t udp_dst_port(unsigned int port) const noexcept
			{
				return Filter_t("udp.DstPort == " + std::to_string(port));
			}

			Filter_t custom_protocol(unsigned int protocol) const noexcept
			{
				return Filter_t("protocol == " + std::to_string(protocol));
			}
			
		};


		template <QVPN::Core::is_filter Filter>
		class WinDivertNetDriver_ : public Filter
		{

		public:

			using Filter_t = Filter::Filter_t;

		private:

			std::vector<Filter_t> filters_;

		public:

			void add_traffic_filter(Filter_t filter)
			{

			}

			void start_capture_traffic()
			{

			}

			void stop_capture_traffic()
			{

			}

		};

		using WinDivertTrafficFilter = WinDivertTrafficFilter_<WinDivertTrafficFilterType>;
		using WinDivertNetDriver = WinDivertNetDriver_<WinDivertTrafficFilter>;
	}


}