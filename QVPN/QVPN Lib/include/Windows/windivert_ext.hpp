#include <windivert.h>
#include <string_view>
#include <string>
#include "lib.hpp"
#include <thread>
#include <stdio.h>
#include <stdlib.h>
#include <chrono>
#include <iostream>
#include <structures.hpp>

#pragma comment(lib, "windivert.lib")


#define MAXBUF              WINDIVERT_MTU_MAX

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
			WinDivertTrafficFilterType& operator=(WinDivertTrafficFilterType filter) noexcept;
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

			Filter_t no_source(const QVPN::Core::IPv4Address& addr) const noexcept
			{
				return Filter_t("localAddr != " + addr.to_string());
			}

			Filter_t no_dest(const QVPN::Core::IPv4Address& addr) const noexcept
			{
				return Filter_t("remoteAddr != " + addr.to_string());
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
			std::string filters_data;
			std::thread worker_;
			HANDLE hDivert_;

			void calculate_filters()
			{
				for (auto& filter : filters_)
				{
					filters_data.append(filter);
				}
			}

			void recalculate_filters()
			{
				filters_data.clear();
				calculate_filters();
			}

			void appy_default_filter(const QVPN::Core::IPv4Address& addr)
			{
				filters_.push_back(addr.to_string());
				calculate_filters();
			}

			void start_capture_traffic_()
			{
				hDivert_ = WinDivertOpen(filters_data.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
				if (hDivert_ != INVALID_HANDLE_VALUE)
				{
					printf("Driver is working.\n");
					
				}
				else
				{
					printf("Error opening driver.\n");
					return;
				}
				capture_loop();
			}

			void capture_loop()
			{
				WINDIVERT_ADDRESS addr;
				UINT8 packet[MAXBUF];
				UINT packet_len;
				PWINDIVERT_IPHDR ip_header;
				PWINDIVERT_TCPHDR tcp_header;
				PVOID payload;
				UINT payload_len;

				auto timer = std::chrono::steady_clock::now();
				auto iter_dur = std::chrono::milliseconds(10);
				while (true)
				{
					if (!WinDivertRecv(hDivert_, packet, sizeof(packet), &packet_len, &addr))
					{
						fprintf(stderr, "warning: failed to read packet (%d)\n",
							GetLastError());
						continue;
					}

					
					WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,
						NULL, NULL, NULL, &tcp_header, NULL, &payload, &payload_len,
						NULL, NULL);
					

					QVPN::Core::DataStructures::Ipv4Packet package(std::begin(packet), std::end(packet));
					std::cout << package.to_friendly_view() << std::endl;
					/*
					auto now = std::chrono::steady_clock::now();
					std::chrono::duration<double, std::milli> timer_diff_ms = timer - now;
					if (timer_diff_ms >= iter_dur)
					{
						if (!WinDivertRecv(hDivert_, packet, sizeof(packet), &packet_len, &addr))
						{
							fprintf(stderr, "warning: failed to read packet (%d)\n",
								GetLastError());
							continue;
						}

						WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,
							NULL, NULL, NULL, &tcp_header, NULL, &payload, &payload_len,
							NULL, NULL);

						printf(static_cast<const char* const>(packet));
						timer = std::chrono::steady_clock::now();

					}
					*/
					/*
					if (ip_header == NULL || tcp_header == NULL || payload == NULL ||
						!BlackListPayloadMatch(blacklist, payload, (UINT16)payload_len))
					{
						// Packet does not match the blacklist; simply reinject it.
						if (!WinDivertSend(handle, packet, packet_len, NULL, &addr))
						{
							fprintf(stderr, "warning: failed to reinject packet (%d)\n",
								GetLastError());
						}
						continue;
					}
					*/
				}
			}

		public:

			void init_driver(const QVPN::Core::IPv4Address& addr)
			{
				appy_default_filter(addr);
			}

			void add_traffic_filter(Filter_t filter)
			{
				filters_.push_back(filter);
				filters_data.append(filter);
			}

			void start_capture_traffic()
			{
				worker_ = std::thread([this]() { start_capture_traffic_(); });
			}

			void stop_capture_traffic()
			{
				WinDivertClose(hDivert_);
				if (worker_.joinable())
				{
					worker_.join();
				}
			}


		};

		using WinDivertTrafficFilter = WinDivertTrafficFilter_<WinDivertTrafficFilterType>;
		using WinDivertNetDriver = WinDivertNetDriver_<WinDivertTrafficFilter>;
	}


}