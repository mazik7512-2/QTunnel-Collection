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
			
			QVPN::Core::PacketPreParser pp;
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
					auto transport_proto = std::visit([](auto& p) { return p.get_ip_protocol(); }, package);
					auto ip_src = std::visit([](auto& p) { return p.get_src_addr(); }, package);
					auto port_src = std::visit([](auto& p) { return p.get_src_port(); }, package);
					auto ip_dest = std::visit([](auto& p) { return p.get_dst_addr(); }, package);
					auto port_dst = std::visit([](auto& p) { return p.get_dst_port(); }, package);

					auto qtunnel_proto_data = std::visit([](auto& p) {return p.collect_proto_data(); }, package);
					

					QVPN::Core::DataStructures::QTunnelProxy<Addr> proxy_data(ver, transport_proto, ip_src, port_src, ip_dest, port_dst, std::move(qtunnel_proto_data));
					auto [data_b, data_e] = std::visit([](auto& p) { return p.get_data(); }, package);
					driver_.encode_and_send(proxy_data, data_b, data_e);

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

					if (decoded_data.has_value())
					{
						auto dst_addr = decoded_data->get_dst_addr();
						auto dst_port = decoded_data->get_dst_port();

						auto [qtp_b, qtp_e] = decoded_data->get_proto_data();

						auto [b, e] = decoded_data->get_raw_data();

						std::visit([&dst_addr, &dst_port, &qtp_b, &qtp_e, &b, &e](auto& p) 
							{ 
								p.set_dst_port(dst_port); 
								p.set_dst_addr(dst_addr);
								p.set_qtunnel_proto_data(qtp_b, qtp_e);
								p.set_data(b, e);
								p.recalculate_checksums();
							}, 
							package);
							
						auto bytes_pair = std::visit([](auto& p) { return p.bytes(); }, package);
						auto size = std::distance(bytes_pair.first, bytes_pair.second);
						if (!WinDivertSend(in_hDivert_, bytes_pair.first, size, NULL, &addr))
						{
							printf("warning: failed to reinject packet (%d)\n",
								GetLastError());
						}
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