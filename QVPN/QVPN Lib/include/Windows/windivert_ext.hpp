#include <windivert.h>
#include <string_view>
#include <string>
#include "lib.hpp"
#include <thread>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <structures.hpp>
#include <fstream>

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

			WinDivertTrafficFilterType();
			WinDivertTrafficFilterType(Convertable_from filter);
			
			WinDivertTrafficFilterType(const WinDivertTrafficFilterType& filter);
			WinDivertTrafficFilterType(WinDivertTrafficFilterType&& filter) noexcept;

			WinDivertTrafficFilterType& operator=(const WinDivertTrafficFilterType& filter);
			WinDivertTrafficFilterType& operator=(WinDivertTrafficFilterType&& filter) noexcept;
			
			WinDivertTrafficFilterType& operator&&(const WinDivertTrafficFilterType& t);
			WinDivertTrafficFilterType& operator||(const WinDivertTrafficFilterType& t);
			WinDivertTrafficFilterType& operator!();
			
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
				return Filter_t("localAddr = " + addr.to_string());
			}

			Filter_t dest(const QVPN::Core::IPv4Address& addr) const noexcept
			{
				return Filter_t("remoteAddr = " + addr.to_string());
			}

			Filter_t src_port(unsigned int port) const noexcept
			{
				return Filter_t("localPort = " + std::to_string(port));
			}

			Filter_t dst_port(unsigned int port) const noexcept
			{
				return Filter_t("remotePort = " + std::to_string(port));
			}

			Filter_t tcp_src_port(unsigned int port) const noexcept
			{
				return Filter_t("tcp.SrcPort = " + std::to_string(port));
			}

			Filter_t tcp_dst_port(unsigned int port) const noexcept
			{
				return Filter_t("tcp.DstPort = " + std::to_string(port));
			}

			Filter_t udp_src_port(unsigned int port) const noexcept
			{
				return Filter_t("udp.SrcPort = " + std::to_string(port));
			}

			Filter_t udp_dst_port(unsigned int port) const noexcept
			{
				return Filter_t("udp.DstPort = " + std::to_string(port));
			}

			Filter_t custom_protocol(unsigned int protocol) const noexcept
			{
				return Filter_t("protocol = " + std::to_string(protocol));
			}

			Filter_t outgoing_traffic() const noexcept
			{
				return Filter_t("outbound");
			}

			Filter_t incoming_traffic() const noexcept
			{
				return Filter_t("inbound");
			}

			Filter_t local_traffic() const noexcept
			{
				return Filter_t("loopback");
			}
			
		};


		template <QVPN::Core::is_filter Filter>
		class WinDivertClientNetDriver_ : public Filter
		{

		public:

			using Filter_t = Filter::Filter_t;

		private:

			std::string outgoing_default_filter_;
			std::string incoming_default_filter_;
			std::vector<Filter_t> filters_;
			std::string outgoing_filters_data;
			std::string incoming_filters_data;
			std::thread out_worker_;
			std::thread in_worker_;
			HANDLE out_hDivert_;
			HANDLE in_hDivert_;
			QVPN::Core::BaseTypes::ULong old_adapter_id;
			QVPN::Core::BaseTypes::ULong new_adapter_id;

			void calculate_outgoing_filters()
			{
				Filter_t temp(outgoing_default_filter_);
				for (auto& filter : filters_)
				{
					temp = temp && filter;
				}
				outgoing_filters_data = temp;
			}

			void apply_default_outgoing_filter(const QVPN::Core::IPv4Address& addr)
			{
				outgoing_default_filter_ = !Filter::source(addr) && Filter::outgoing_traffic();
				calculate_outgoing_filters();
			}

			void start_capture_outgoing_traffic_(const QVPN::Core::IPv4Address& adapter_addr)
			{
				out_hDivert_ = WinDivertOpen(outgoing_filters_data.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
				if (out_hDivert_ != INVALID_HANDLE_VALUE)
				{
					printf("Driver is working.\n");
					
				}
				else
				{
					printf("Error opening driver.\n");
					return;
				}
				outgoing_capture_loop(adapter_addr);
			}

			void outgoing_capture_loop(const QVPN::Core::IPv4Address& adapter_addr)
			{
				WINDIVERT_ADDRESS addr;
				UINT8 packet[MAXBUF];
				UINT packet_len;
				PWINDIVERT_IPHDR ip_header;
				PWINDIVERT_TCPHDR tcp_header;
				PVOID payload;
				UINT payload_len;

				while (true)
				{
					if (!WinDivertRecv(out_hDivert_, packet, sizeof(packet), &packet_len, &addr))
					{
						fprintf(stderr, "warning: failed to read packet (%d)\n",
							GetLastError());
						continue;
					}
					
					old_adapter_id = addr.Network.IfIdx;

					QVPN::Core::DataStructures::Ipv4TcpPacket_View package(packet, packet + packet_len);
					//package.set_ip_source(adapter_addr);
					package.recalculate_ip_checksum();
					std::cout << "Out " << package.ip_to_friendly_view() << std::endl;
					QVPN::Core::BaseTypes::UByte test[5] = { 't', 'e', 's', 't', '\0' };
					package.set_data(std::begin(test), std::end(test));
					//addr.Network.IfIdx = new_adapter_id; // <-- 0x10

					auto [b, e] = package.bytes();
					if (!WinDivertSend(out_hDivert_, b, e - b, NULL, &addr)) // <------ addr структура WinDivert которую надо изменять??
					{
						fprintf(stderr, "warning: failed to reinject packet (%d)\n",
							GetLastError());
					}

				}
			}


			void calculate_incoming_filters()
			{
				Filter_t temp(incoming_default_filter_);
				for (auto& filter : filters_)
				{
					temp = temp && filter;
				}
				incoming_filters_data = temp;
			}

			void apply_default_incoming_filter(const QVPN::Core::IPv4Address& addr)
			{
				incoming_default_filter_ = Filter::incoming_traffic();
				calculate_incoming_filters();
			}

			void start_capture_incoming_traffic_(const QVPN::Core::IPv4Address& adapter_addr)
			{
				in_hDivert_ = WinDivertOpen(incoming_filters_data.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
				printf(incoming_filters_data.c_str());
				if (in_hDivert_ != INVALID_HANDLE_VALUE)
				{
					printf("Driver is working.\n");

				}
				else
				{
					printf("Error opening driver.\n");
					return;
				}
				incoming_capture_loop(adapter_addr);
			}

			void incoming_capture_loop(const QVPN::Core::IPv4Address& adapter_addr)
			{
				WINDIVERT_ADDRESS addr;
				UINT8 packet[MAXBUF];
				UINT packet_len;
				PWINDIVERT_IPHDR ip_header;
				PWINDIVERT_TCPHDR tcp_header;
				PVOID payload;
				UINT payload_len;

				using UShort = QVPN::Core::BaseTypes::UShort;
				using UByte = QVPN::Core::BaseTypes::UByte;
				using UInt = QVPN::Core::BaseTypes::UInt;
				

				while (true)
				{
					if (!WinDivertRecv(in_hDivert_, packet, sizeof(packet), &packet_len, &addr))
					{
						printf("warning: failed to read packet (%d)\n",
							GetLastError());
						continue;
					}


					WinDivertHelperParsePacket(packet, packet_len, &ip_header, nullptr,
						NULL, nullptr, nullptr, &tcp_header, nullptr, NULL,
						&payload_len, NULL, NULL);

					auto packet_start = packet;
					auto packet_end = packet + packet_len;
					QVPN::Core::DataStructures::Ipv4TcpPacket_View package(packet_start, packet_end);
					std::cout << "In " << package.ip_to_friendly_view() << std::endl;
					std::cout << package.tcp_to_friendly_view() << std::endl;
					auto c = package.get_tcp_checksum();
					auto d = tcp_header->Checksum;
					//package.set_ip_dest(adapter_addr); 
					package.recalculate_checksums();
					auto c1 = package.get_tcp_checksum();
					auto d1 = tcp_header->Checksum;


					//package.set_data(std::begin(test), std::end(test)); 
					auto [begin, end] = package.bytes();
					
					//addr.Network.IfIdx = old_adapter_id;

					if (!WinDivertSend(in_hDivert_, begin, end - begin, NULL, &addr))
					{
						printf("warning: failed to reinject packet (%d)\n",
							GetLastError());
					}

				}
			}

		public:

			
			void init_driver(const QVPN::Core::IPv4Address& addr)
			{
				apply_default_outgoing_filter(addr);
				apply_default_incoming_filter(addr);
			}
			
			void add_outgoing_traffic_filter(Filter_t filter)
			{
				filters_.push_back(filter);
				calculate_outgoing_filters();
			}

			void add_incoming_traffic_filter(Filter_t filter)
			{
				filters_.push_back(filter);
				calculate_incoming_filters();
			}

			void start_capture_outgoing_traffic(const QVPN::Core::IPv4Address& adapter_addr, QVPN::Core::BaseTypes::ULong adapter_id)
			{
				new_adapter_id = adapter_id;
				//out_worker_ = std::thread([this, &adapter_addr]() { start_capture_outgoing_traffic_(adapter_addr); });
				//start_capture_outgoing_traffic_(adapter_addr);
			}

			void start_capture_incoming_traffic(const QVPN::Core::IPv4Address& adapter_addr)
			{
				//in_worker_ = std::thread([this, &adapter_addr]() { start_capture_incoming_traffic_(adapter_addr); });
				start_capture_incoming_traffic_(adapter_addr);
			}

			void stop_capture_traffic()
			{
				WinDivertClose(out_hDivert_);
				WinDivertClose(in_hDivert_);
				if (out_worker_.joinable())
				{
					out_worker_.join();
				}
				if (in_worker_.joinable())
				{
					in_worker_.join();
				}
			}


		};

		using WinDivertTrafficFilter = WinDivertTrafficFilter_<WinDivertTrafficFilterType>;
		using WinDivertClientNetDriver = WinDivertClientNetDriver_<WinDivertTrafficFilter>;
	}


}