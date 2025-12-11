#include <qvpn_net_tools.hpp>
#include <qvpn_driver.hpp>
#include <windivert.h>
#include <string_view>
#include <string>
#include <thread>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <qvpn_structures.hpp>
#include <fstream>
#include <qvpn_tools.hpp>
#include <variant>



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

			Filter_t source(const QVPN::Core::NetAddr& addr) const noexcept
			{
				return Filter_t("localAddr = " + addr.to_string());
			}

			Filter_t dest(const QVPN::Core::IPv4Address& addr) const noexcept
			{
				return Filter_t("remoteAddr = " + addr.to_string());
			}

			Filter_t dest(const QVPN::Core::NetAddr& addr) const noexcept
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


		template <QVPN::Core::is_filter Filter, QVPN::Core::is_vpn_client_driver VPNDriver>
		class WinDivertClientNetDriver_ : public Filter
		{
		public:

			using Filter_t = Filter::Filter_t;
			using Addr = VPNDriver::AddrType;

		private:


			std::vector<Filter_t> filters_out_;
			std::vector<Filter_t> filters_in_;

			std::string outgoing_filters_data;
			std::string incoming_filters_data;

			std::thread out_worker_;
			std::thread in_worker_;

			HANDLE out_hDivert_;
			HANDLE in_hDivert_;

			QVPN::Core::BaseTypes::ULong old_adapter_id;
			QVPN::Core::BaseTypes::ULong new_adapter_id;
			
			QVPN::Core::PreParser pp;
			VPNDriver driver_;

			void calculate_outgoing_filters()
			{
				Filter_t temp("");
				apply_default_outgoing_filter();
				for (auto& filter : filters_out_)
				{
					temp = temp && filter;
				}
				outgoing_filters_data = temp;
			}

			void apply_default_outgoing_filter()
			{
				filters_out_.push_back(!Filter::dest(driver_.get_vpn_address()));
				filters_out_.push_back(Filter::outgoing_traffic());
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

					//package.set_ip_source(adapter_addr);
					//addr.Network.IfIdx = new_adapter_id; // <-- 0x10
					
					auto package = pp.pre_parse(packet, packet + packet_len);

					auto ver = std::visit([](auto& p) { return p.get_ip_version(); }, package);
					auto net_proto = std::visit([](auto& p) { return p.get_ip_protocol(); }, package);
					auto ip_dest = std::visit([](auto& p) { return p.get_ip_dest(); }, package);
					auto port_dst = std::visit([](auto& p) { return p.get_dst_port(); }, package);

					QVPN::Core::DataStructures::QVPNProxyData<Addr> proxy_data{ ver, net_proto, ip_dest, port_dst };
					auto [data_b, data_e] = std::visit([](auto& p) { return p.get_data(); }, package);
					auto encoded_data = driver_.encode_data(proxy_data, data_b, data_e);

					const auto new_dest_ip = driver_.get_vpn_address();
					const auto new_dest_port = driver_.get_vpn_port();
					
					std::visit([&new_dest_ip, &new_dest_port](auto& p) 
						{ 
							p.set_dst_addr(new_dest_ip);
							p.set_dst_port(new_dest_port);
							p.recalculate_checksums();
						}
					, package);


					auto encoded_package = std::visit([&encoded_data](auto& p)
						{
							return p.set_data(encoded_data.begin(), encoded_data.end());
						},
						package);
					
					// TODO: сделать отправку пакета через сокет, а не через WinDivert, либо что-то придумать с вовзращаемым типом set_data


					auto [e_b, e_e] = encoded_package.bytes();
					auto e_size = std::distance(e_b, e_e);

					if (!WinDivertSend(out_hDivert_, e_b, e_size, NULL, &addr)) // <------ addr структура WinDivert которую надо изменять??
					{
						fprintf(stderr, "warning: failed to reinject packet (%d)\n",
							GetLastError());
					}

				}
			}


			void calculate_incoming_filters()
			{
				Filter_t temp("");
				apply_default_incoming_filter();
				for (auto& filter : filters_out_)
				{
					temp = temp && filter;
				}
				incoming_filters_data = temp;
			}

			void apply_default_incoming_filter()
			{
				filters_in_.push_back(Filter::incoming_traffic());
				filters_in_.push_back(Filter::source(driver_.get_vpn_address()));
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

					auto package = pp.pre_parse(packet, packet + packet_len);
					auto [data_b, data_e] = std::visit([](auto& p) { return p.get_data(); }, package);
					auto decoded_data = driver_.decode_data(data_b, data_e);
					
					if (!WinDivertSend(in_hDivert_, decoded_data.data(), decoded_data.size(), NULL, &addr))
					{
						printf("warning: failed to reinject packet (%d)\n",
							GetLastError());
					}
					
				}
			}

		public:

			WinDivertClientNetDriver_(QVPN::Core::QVPNClientSettings settings)
				: driver_(std::move(settings))
			{

			}

			void init_driver(const QVPN::Core::IPv4Address& addr)
			{
				apply_default_outgoing_filter(addr);
				apply_default_incoming_filter(addr);
			}
			
			void add_outgoing_traffic_filter(Filter_t filter)
			{
				filters_out_.push_back(filter);
				calculate_outgoing_filters();
			}

			void add_incoming_traffic_filter(Filter_t filter)
			{
				filters_out_.push_back(filter);
				calculate_incoming_filters();
			}

			void start_capture_outgoing_traffic(const QVPN::Core::IPv4Address& adapter_addr, QVPN::Core::BaseTypes::ULong adapter_id)
			{
				driver_.connect();
				driver_.init();
				new_adapter_id = adapter_id;
				//out_worker_ = std::thread([this, &adapter_addr]() { start_capture_outgoing_traffic_(adapter_addr); });
				start_capture_outgoing_traffic_(adapter_addr);
			}

			void start_capture_incoming_traffic(const QVPN::Core::IPv4Address& adapter_addr)
			{
				in_worker_ = std::thread([this, &adapter_addr]() { start_capture_incoming_traffic_(adapter_addr); });
				//start_capture_incoming_traffic_(adapter_addr);
			}

			void stop_capture_traffic()
			{
				driver_.disconnect();
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

		using WinQVPNDriver = QVPN::Core::QVPNClientDriver<QVPN::Core::BaseTypes::UByte*, QVPN::Core::NetAddr, QVPN::NetTools::QVPN_Socket, QVPN::NetTools::QVPNNetTools>;

		using WinDivertTrafficFilter = WinDivertTrafficFilter_<WinDivertTrafficFilterType>;
		using WinDivertClientNetDriver = WinDivertClientNetDriver_<WinDivertTrafficFilter, WinQVPNDriver>;
	}


}