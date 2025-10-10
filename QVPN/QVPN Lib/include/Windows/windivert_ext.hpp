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
				return Filter_t("localAddr ==");
			}

			Filter_t dest(const QVPN::Core::IPv4Address& addr) const noexcept
			{
				return Filter_t("remoteAddr ==");
			}

			Filter_t source_port(unsigned int port) const noexcept
			{
				return Filter_t("localPor t==");
			}

			Filter_t dest_port(unsigned int port) const noexcept
			{
				return Filter_t("remotePort ==");
			}

			Filter_t tcp_source_port(unsigned int port) const noexcept
			{
				return Filter_t("tcp.SrcPort ==");
			}

			Filter_t tcp_dest_port(unsigned int port) const noexcept
			{
				return Filter_t("tcp.DstPort ==");
			}

			Filter_t udp_source_port(unsigned int port) const noexcept
			{
				return Filter_t("udp.SrcPort ==");
			}

			Filter_t udp_dest_port(unsigned int port) const noexcept
			{
				return Filter_t("udp.DstPort ==");
			}

			Filter_t custom_protocol() const noexcept
			{
				return Filter_t("protocol ==");
			}
			
		};

		using WinDivertTrafficFilter = WinDivertTrafficFilter_<WinDivertTrafficFilterType>;
	}

}