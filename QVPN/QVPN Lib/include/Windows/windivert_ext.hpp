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
				return Filter_t("ip.SrcAddr = " + addr.to_string());
			}

			Filter_t source(const QVPN::Core::NetAddr& addr) const noexcept
			{
				switch (addr.get_addr_family())
				{
				case QVPN::Core::IPv4:
					return Filter_t("ip.SrcAddr = " + addr.to_string());
				case QVPN::Core::IPv6:
					return Filter_t("ip6.SrcAddr = " + addr.to_string());
				default:
					return Filter_t("Address type not supported");
				}
				
			}

			Filter_t dest(const QVPN::Core::IPv4Address& addr) const noexcept
			{
				return Filter_t("ip.DstAddr = " + addr.to_string());
			}

			Filter_t dest(const QVPN::Core::NetAddr& addr) const noexcept
			{
				switch (addr.get_addr_family())
				{
				case QVPN::Core::IPv4:
					return Filter_t("ip.DstAddr = " + addr.to_string());
				case QVPN::Core::IPv6:
					return Filter_t("ip6.DstAddr = " + addr.to_string());
				default:
					return Filter_t("Address type not supported");
				}
			}

			Filter_t src_port(unsigned int port) const noexcept
			{
				return Filter_t("tcp.SrcPort = " + std::to_string(port) + " || udp.SrcPort = " + std::to_string(port));
			}

			Filter_t dst_port(unsigned int port) const noexcept
			{
				return Filter_t("tcp.DstPort = " + std::to_string(port) + " || udp.DstPort = " + std::to_string(port));
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
			
			Filter_t injected() const noexcept
			{
				return Filter_t("impostor");
			}

		};


		template <QVPN::Core::is_filter Filter, QVPN::Core::is_vpn_client_driver VPNDriver, QVPN::Core::is_logger Logger>
		class WinDivertClientVPNNetDriver_ : public Filter
		{
		public:

			using Filter_t = Filter::Filter_t;
			using Addr = VPNDriver::AddrType;
			using UByte = QVPN::Core::BaseTypes::UByte;
			using UInt = QVPN::Core::BaseTypes::UInt;

		private:

			template <class AppLevelProtoTemplate>
			using SafeReceiveData = QVPN::Core::SafeReceiveData<AppLevelProtoTemplate>;

			std::vector<Filter_t> filters_out_;
			std::vector<Filter_t> filters_in_;

			std::string outgoing_filters_data;
			std::string incoming_filters_data;

			std::thread out_worker_;
			std::thread in_worker_;
			std::thread dummy_worker_;

			HANDLE out_hDivert_;
			HANDLE in_hDivert_;

			QVPN::Core::BaseTypes::ULong old_adapter_id;
			QVPN::Core::BaseTypes::ULong new_adapter_id;
			
			QVPN::Core::PacketPreParser pp;
			VPNDriver driver_;
			Logger logger_{};
			bool vpn_connected_ = false;

			QVPN::Core::Tools::QVPNSpeedMeter speed_meter_{};

		private:


			auto generate_transport_bytes_by_proxy_data(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& proxy_data) const
			{
				auto t_proto = proxy_data.get_transport_proto();
				auto [b, e] = proxy_data.get_proto_data_bytes();

				switch (t_proto)
				{
				case QVPN::Core::TransportProtocol::TCP:
				{
					QVPN::Core::DataStructures::QTunnelTCPViewScheme scheme(b, e);
					auto [opt_b, opt_e] = scheme.get_options();
					return QVPN::Core::DataStructures::TcpPacketView::generate_object_bytes(proxy_data.get_src_port(), proxy_data.get_dst_port(), scheme.get_seq(), scheme.get_ack(), scheme.get_offset(),
						scheme.get_flags(), scheme.get_window(), scheme.get_urgent_pointer(), opt_b, opt_e);
				}
				case QVPN::Core::TransportProtocol::UDP:
				{
					QVPN::Core::DataStructures::QTunnelUDPViewScheme scheme(b, e);
					return QVPN::Core::DataStructures::UdpPacketView::generate_object_bytes(proxy_data.get_src_port(), proxy_data.get_dst_port(), scheme.get_length());
				}
				default:
					return std::vector<UByte>{};
				}
			}

			auto generate_net_bytes_by_proxy_data(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& proxy_data, UByte* begin, UByte* end, QVPN::Core::BaseTypes::UShort transport_length, bool dont_fragment = true, bool more_fragment = false, QVPN::Core::BaseTypes::UShort offset = 0) const
			{
				auto packet_data_size = std::distance(begin, end);
				auto total_length = packet_data_size + transport_length;
				auto n_proto = proxy_data.get_net_proto();
				QVPN::Core::DataStructures::IPv4DefaultGenStrategy ipv4_gen{};
				switch (n_proto)
				{
				case QVPN::Core::NetProtocol::IPv4:
					return QVPN::Core::DataStructures::Ipv4PacketView::generate_object_bytes<QVPN::Core::DataStructures::IPv4DefaultGenStrategy>(ipv4_gen, proxy_data.get_src_addr(), proxy_data.get_dst_addr(), proxy_data.get_transport_proto(), 
						total_length, dont_fragment, more_fragment, offset);
				default:
					return std::vector<UByte>{};
				}
			}

			auto generate_packet_bytes_by_proxy_data(const QVPN::Core::DataStructures::QTunnelProxy<Addr>& proxy_data, UByte* begin, UByte* end) const
			{
				auto t_header = generate_transport_bytes_by_proxy_data(proxy_data);
				auto n_header = generate_net_bytes_by_proxy_data(proxy_data, begin, end, t_header.size());

				std::vector<UByte> bytes{};
				bytes.insert(bytes.end(), n_header.begin(), n_header.end());
				bytes.insert(bytes.end(), t_header.begin(), t_header.end());
				bytes.insert(bytes.end(), begin, end);

				auto packet = pp.pre_parse(bytes.data(), bytes.data() + bytes.size());

				std::visit([](auto& p) { p.recalculate_lengths(); p.recalculate_checksums(); }, packet);

				return bytes;

			}


			void clear_outgoing_filters()
			{
				filters_out_.clear();
				outgoing_filters_data.clear();
			}

			void calculate_outgoing_filters()
			{
				Filter_t temp("");
				for (auto& filter : filters_out_)
				{
					temp = temp && filter;
				}
				outgoing_filters_data = temp;
			}

			void apply_default_outgoing_filter()
			{
				filters_out_.push_back(!Filter::source(driver_.get_vpn_address())); //for localhost server
				//filters_out_.push_back(!Filter::dest(driver_.get_vpn_address())); // for client outgoing traffic
				filters_out_.push_back(Filter::outgoing_traffic());
				filters_out_.push_back(!Filter::tcp_dst_port(22)); // not ssh
				filters_out_.push_back(!Filter::local_traffic());
				filters_out_.push_back(!Filter::injected());

				filters_out_.push_back(Filter::dest(Addr("0.0.0.0")));
				filters_out_.push_back(Filter::tcp_dst_port(8080));
			}

			void start_capture_outgoing_traffic_(const QVPN::Core::IPv4Address& adapter_addr)
			{
				logger_.info("Filters (out): {}", outgoing_filters_data);
				out_hDivert_ = WinDivertOpen(outgoing_filters_data.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
				if (out_hDivert_ != INVALID_HANDLE_VALUE)
				{
					logger_.success("Driver is working.");
				}
				else
				{
					logger_.fail("Error opening driver.\n");
					return;
				}
				outgoing_capture_loop(adapter_addr);
			}

			

			void outgoing_capture_loop(const QVPN::Core::IPv4Address& adapter_addr)
			{
				/*
				WINDIVERT_ADDRESS addr;
				UINT8 packet[MAXBUF];
				UINT packet_len;
				PWINDIVERT_IPHDR ip_header;
				PWINDIVERT_TCPHDR tcp_header;
				PVOID payload;
				UINT payload_len;
				*/

				constexpr UInt BATCH_SIZE = 3;                    // Максимум пакетов за один приём
				constexpr size_t MAX_PKT_LEN = 65536;                 // Максимальная длина одного пакета
				constexpr size_t BUF_LEN = BATCH_SIZE * MAX_PKT_LEN; // Общий размер буфера

				std::vector<UINT8> packetBuffer_{};
				packetBuffer_.reserve(BUF_LEN);
				packetBuffer_.resize(BUF_LEN);

				WINDIVERT_ADDRESS addr[BATCH_SIZE];

				std::vector<QVPN::Core::DataStructures::BatchPacketsItemView<Addr>> res_packets{}; // packets getting from decode ONE batch
				std::vector<WINDIVERT_ADDRESS> res_addrs{}; // addrs getting from decode ONE batch
				res_packets.reserve(BATCH_SIZE);
				res_addrs.reserve(BATCH_SIZE);

				std::stringstream ss{};

				while (vpn_connected_)
				{

					UINT readLen = 0;
					UINT addrLen = sizeof(addr);
					size_t packets_counter = 0;

					// flags должен быть 0, overlapped = NULL — синхронный режим
					if (!WinDivertRecvEx(out_hDivert_, packetBuffer_.data(), BUF_LEN, &readLen,
						0, addr, &addrLen, NULL)) {
						std::cerr << "RecvEx failed: " << GetLastError() << "\n";
						continue;
					}

					// addrLen — это РАЗМЕР В БАЙТАХ, количество пакетов = addrLen / sizeof(WINDIVERT_ADDRESS)
					UInt numPackets = addrLen / sizeof(WINDIVERT_ADDRESS);
					std::cout << "Received " << static_cast<UInt>(numPackets) << " packets, "
						<< readLen << " bytes total\n";

					auto packets = pp.pre_parse_cycled(packetBuffer_.data(), packetBuffer_.data() + readLen);
					auto packets_num = packets.size();

					res_packets.clear();
					res_addrs.clear();

					for (size_t i = 0; i < packets_num; i++)
					{
						addr[i].Impostor = true;

						auto& package = packets[i];

						auto ver = std::visit([](auto& p) { return p.get_protocol_version(); }, package);
						auto transport_proto = std::visit([](auto& p) { return p.get_transport_protocol(); }, package);
						auto ip_src = std::visit([](auto& p) { return p.get_src_addr(); }, package);
						auto port_src = std::visit([](auto& p) { return p.get_src_port(); }, package);
						auto ip_dest = std::visit([](auto& p) { return p.get_dst_addr(); }, package);
						auto port_dst = std::visit([](auto& p) { return p.get_dst_port(); }, package);

						auto qtunnel_proto_data = std::visit([](auto& p) {return p.collect_proto_data(); }, package);

						QVPN::Core::DataStructures::QTunnelProxy<Addr> proxy_data(ver, transport_proto, ip_src, port_src, ip_dest, port_dst, std::move(qtunnel_proto_data));
						auto [data_b, data_e] = std::visit([](auto& p) { return p.get_payload(); }, package);
						std::visit([](auto& p) {std::cout << "outgoing capture" << std::endl << p.to_packet_friendly_view() << std::endl; }, package);
						res_packets.emplace_back(proxy_data, data_b, data_e);
						speed_meter_.add_send_size(std::distance(data_b, data_e));
						logger_.info("Send speed. Avg Speed = {}.", speed_meter_.get_average_send_speed()); // TODO: разобраться со спидометром
					}
					driver_.encode_and_send(res_packets.data(), res_packets.data() + res_packets.size());

					/*
					if (!WinDivertRecv(out_hDivert_, packet, sizeof(packet), &packet_len, &addr))
					{
						logger_.fail("Failed to read packet. Error #{}", GetLastError());
						continue;
					}
					addr.Impostor = true;

					auto package = pp.pre_parse(packet, packet + packet_len);

					auto ver = std::visit([](auto& p) { return p.get_protocol_version(); }, package);
					auto transport_proto = std::visit([](auto& p) { return p.get_transport_protocol(); }, package);
					auto ip_src = std::visit([](auto& p) { return p.get_src_addr(); }, package);
					auto port_src = std::visit([](auto& p) { return p.get_src_port(); }, package);
					auto ip_dest = std::visit([](auto& p) { return p.get_dst_addr(); }, package);
					auto port_dst = std::visit([](auto& p) { return p.get_dst_port(); }, package);

					auto qtunnel_proto_data = std::visit([](auto& p) {return p.collect_proto_data(); }, package);

					QVPN::Core::DataStructures::QTunnelProxy<Addr> proxy_data(ver, transport_proto, ip_src, port_src, ip_dest, port_dst, std::move(qtunnel_proto_data));
					auto [data_b, data_e] = std::visit([](auto& p) { return p.get_payload(); }, package);
					std::visit([](auto& p) {std::cout << "outgoing capture" << std::endl << p.to_packet_friendly_view() << std::endl; }, package);
					driver_.encode_and_send(proxy_data, data_b, data_e);
					speed_meter_.add_send_size(std::distance(data_b, data_e));
					logger_.info("Send speed. Avg Speed = {}.", speed_meter_.get_average_send_speed()); // TODO: разобраться со спидометром
					*/
				}
			}

			void clear_incoming_filters()
			{
				filters_in_.clear();
				incoming_filters_data.clear();
			}

			void calculate_incoming_filters()
			{
				Filter_t temp("");
				for (auto& filter : filters_in_)
				{
					temp = temp && filter;
				}
				incoming_filters_data = temp;
			}

			void apply_default_incoming_filter()
			{
				filters_in_.push_back(Filter::incoming_traffic());
				filters_in_.push_back(Filter::source(driver_.get_vpn_address()));
				filters_in_.push_back(!Filter::tcp_src_port(22)); // not ssh
				filters_in_.push_back(!Filter::local_traffic());
				filters_in_.push_back(!Filter::injected());

				filters_in_.push_back(Filter::source(Addr("0.0.0.0")));
			}

			void start_capture_incoming_traffic_(const QVPN::Core::IPv4Address& adapter_addr)
			{
				logger_.info("Filters: {}", incoming_filters_data);
				in_hDivert_ = WinDivertOpen(incoming_filters_data.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
				if (in_hDivert_ != INVALID_HANDLE_VALUE)
				{
					logger_.success("Driver is working.");

				}
				else
				{
					logger_.fail("Error opening driver. Error #", GetLastError());
					return;
				}
				incoming_capture_loop(adapter_addr);
			}

			void incoming_capture_loop(const QVPN::Core::IPv4Address& adapter_addr)
			{

				constexpr UInt BATCH_SIZE = 5;                    // Максимум пакетов за один приём
				constexpr size_t MAX_PKT_LEN = 65536;                 // Максимальная длина одного пакета
				constexpr size_t BUF_LEN = BATCH_SIZE * MAX_PKT_LEN; // Общий размер буфера

				std::vector<UINT8> packetBuffer_{};
				packetBuffer_.reserve(BUF_LEN);
				packetBuffer_.resize(BUF_LEN);

				WINDIVERT_ADDRESS addr[BATCH_SIZE];

				std::vector<UByte> res_packets{}; // packets getting from decode ONE batch
				std::vector<WINDIVERT_ADDRESS> res_addrs{}; // addrs getting from decode ONE batch
				res_packets.reserve(BUF_LEN);
				res_addrs.reserve(BATCH_SIZE);
				
				while (vpn_connected_) {
					UINT readLen = 0;
					UINT addrLen = sizeof(addr); 
					size_t packets_counter = 0;

					// flags должен быть 0, overlapped = NULL — синхронный режим
					if (!WinDivertRecvEx(in_hDivert_, packetBuffer_.data(), BUF_LEN, &readLen,
						0, addr, &addrLen, NULL)) {
						std::cerr << "RecvEx failed: " << GetLastError() << "\n";
						continue;
					}

					// addrLen — это РАЗМЕР В БАЙТАХ, количество пакетов = addrLen / sizeof(WINDIVERT_ADDRESS)
					UInt numPackets = addrLen / sizeof(WINDIVERT_ADDRESS);
					std::cout << "Received " << static_cast<UInt>(numPackets) << " packets, "
						<< readLen << " bytes total\n";

					UINT sentLen = 0;
					if (!WinDivertSendEx(in_hDivert_, packetBuffer_.data(), readLen,
						&sentLen, 0, addr, addrLen, NULL)) {
						std::cerr << "First SendEx failed: " << GetLastError() << "\n";
					}
					else {
						std::cout << "First Sent back " << sentLen << " bytes\n";
					}

					auto packets = pp.pre_parse_cycled(packetBuffer_.data(), packetBuffer_.data() + readLen);
					auto packets_num = packets.size();

					res_packets.clear();
					res_addrs.clear();

					for (size_t i = 0; i < packets_num; i++)
					{
						auto [data_b, data_e] = std::visit([](auto& packet) { return packet.get_payload(); }, packets[i]);

						if (std::distance(data_b, data_e) == 0)
							continue;

						SafeReceiveData<QVPN::Core::DataStructures::TLS13_RecordLittleEndian> sf_data{};

						sf_data.add_objects_and_validate(QVPN::Core::SafeReceiveSignal::SFR_NO_DATA, data_b, data_e);
						auto num_obj = sf_data.get_objects_num();

						for (size_t j = 0; j < num_obj; j++)
						{
							auto [obj_b, obj_e] = sf_data.get_object_bytes(j);

							auto decoded_data = driver_.decode_data(obj_b, obj_e);
							if (decoded_data.has_value())
							{
								if (!decoded_data->check_validity())
									continue;

								auto dst_addr = decoded_data->get_dst_addr();
								auto dst_port = decoded_data->get_dst_port();
								auto src_addr = decoded_data->get_src_addr();
								auto src_port = decoded_data->get_src_port();

								auto [qtp_b, qtp_e] = decoded_data->get_proto_data_bytes();

								auto [b, e] = decoded_data->get_raw_data();

								using ProxyData = QVPN::Core::DataStructures::QTunnelProxy<Addr>;

								auto proxy_data = decoded_data->create(*decoded_data);

								auto inj_p_bytes = std::visit([&proxy_data, &b, &e](auto& p) { return p.new_packet_bytes_by_this(proxy_data, b, e); }, packets[i]);
								auto inj_packet = pp.pre_parse(inj_p_bytes.data(), inj_p_bytes.data() + inj_p_bytes.size());

								// TODO: сделать аллокатор для пакета, либо выделять память раньше

								std::visit([](auto& p) { std::cout << "Incoming packet (after modified)" << std::endl << p.to_packet_friendly_view() << std::endl; }, inj_packet);
								auto [res_b, res_e] = std::visit([](auto& p) { return p.bytes(); }, inj_packet);

								res_packets.insert(res_packets.end(), res_b, res_e);
								addr[i].Impostor = true;
								res_addrs.push_back(addr[i]);
								packets_counter++;
							}
						}
					}

					if (packets_counter == 0)
						continue;

					sentLen = 0;
					if (!WinDivertSendEx(in_hDivert_, res_packets.data(), res_packets.size(),
						&sentLen, 0, res_addrs.data(), res_addrs.size() * sizeof(WINDIVERT_ADDRESS), NULL)) {
						std::cerr << "Second SendEx failed: " << GetLastError() << "\n";
					}
					else {
						std::cout << "Second Sent back " << sentLen << " bytes\n";
					}
					auto _ = driver_.get_data();
				}


				/*
				// TODO: нужно разобраться с восстановлением подключения, возможно на сервере?
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

				// TODO: попробовать WinDivertRecvEx и WinDivertSendEx + возможно складывать их в буфер и оттуда обрабатывать, а recv и send в отдельном потоке


				WinDivertSetParam(in_hDivert_, WINDIVERT_PARAM_QUEUE_TIME, 2000000);

				while (vpn_connected_)
				{
					if (!WinDivertRecv(in_hDivert_, packet, sizeof(packet), &packet_len, &addr))
					{
						logger_.fail("Failed to read packet. Error #{}", GetLastError());
						continue;
					}
					
					speed_meter_.add_receive_size(packet_len);
					logger_.success("Received packet. Packet size = {}. Avg Speed = {}.", packet_len, speed_meter_.get_average_recv_speed());

					addr.Impostor = true;

					if (!WinDivertSend(in_hDivert_, packet, sizeof(packet), &packet_len, &addr))
					{
						logger_.fail("Failed to reinject incoming packet. Error #{}", GetLastError());
					}
					
					auto package = pp.pre_parse(packet, packet + packet_len);
					
					auto [data_b, data_e] = std::visit([](auto& p) { return p.get_payload(); }, package);

					auto data_size = std::distance(data_b, data_e);
					if (data_size == 0) // this is not our packet
					{
						continue;
						// все что ниже не нужно
						logger_.warning("This is not our packet. Zero payload size.");
						if (!WinDivertSend(in_hDivert_, packet, sizeof(packet), &packet_len, &addr))
						{
							logger_.fail("Failed to reinject incoming packet (not our). Error #{}", GetLastError());
							continue;
						}
						logger_.warning("Packet (not our) succesfully reinjected.");
						continue;
						// дальше нужно
					}
					
					SafeReceiveData<QVPN::Core::DataStructures::TLS13_RecordLittleEndian> sf_data{};

					sf_data.add_objects_and_validate(QVPN::Core::SafeReceiveSignal::SFR_NO_DATA, data_b, data_e);
					auto num_obj = sf_data.get_objects_num();
					//auto num_obj = data.get_objects_num();
					logger_.success("Received {} objects from safe receive", num_obj);
					for (size_t i = 0; i < num_obj; i++)
					{
						auto [obj_b, obj_e] = sf_data.get_object_bytes(i);
						auto decoded_data = driver_.decode_data(obj_b, obj_e); // TODO: подчистить код

						if (decoded_data.has_value())
						{
							if (!decoded_data->check_validity())
								continue;

							auto dst_addr = decoded_data->get_dst_addr();
							auto dst_port = decoded_data->get_dst_port();
							auto src_addr = decoded_data->get_src_addr();
							auto src_port = decoded_data->get_src_port();

							auto [qtp_b, qtp_e] = decoded_data->get_proto_data_bytes();

							auto [b, e] = decoded_data->get_raw_data();

							using ProxyData = QVPN::Core::DataStructures::QTunnelProxy<Addr>;

							auto proxy_data = decoded_data->create(*decoded_data);

							auto inj_p_bytes = std::visit([&proxy_data, &b, &e](auto& p) { return p.new_packet_bytes_by_this(proxy_data, b, e); }, package);
							auto inj_packet = pp.pre_parse(inj_p_bytes.data(), inj_p_bytes.data() + inj_p_bytes.size());
							//auto inj_p_bytes = generate_packet_bytes_by_proxy_data(proxy_data, b, e);
							//auto inj_packet = pp.pre_parse(inj_p_bytes.data(), inj_p_bytes.data() + inj_p_bytes.size());

							// TODO: сделать аллокатор для пакета, либо выделять память раньше

							std::visit([](auto& p) { std::cout << "Incoming packet (after modified)" << std::endl << p.to_packet_friendly_view() << std::endl; }, inj_packet);
							auto [res_b, res_e] = std::visit([](auto& p) { return p.bytes(); }, inj_packet);
							UINT size = static_cast<UINT>(std::distance(res_b, res_e));
							//WinDivertHelperCalcChecksums((void*)res_b, size, &addr, 0);
							//std::visit([](auto& p) { std::cout << "Incoming packet (after recalc)" << std::endl << p.to_packet_friendly_view() << std::endl; }, inj_packet);
							if (!WinDivertSend(in_hDivert_, res_b, inj_p_bytes.size(), &size, &addr))
							{
								logger_.fail("Failed to reinject incoming packet. Error #{}", GetLastError());
								continue;
							}
							logger_.success("Packet successfully reinject into original connection.");
						}

					logger_.info("Waiting for packet from get_data...");
					auto data = driver_.get_data(); // dummy recv
					
					if (!data.status.success)
					{
						logger_.fail("Failed to get_data. Error # {}. {}", data.status.status, strerror(data.status.status));
					}

					//auto data_b = data.data.data();
					//auto data_e = data.data.data() + data.size;

					//std::visit([](auto& p) { std::cout << "Incoming packet" << std::endl << p.to_packet_friendly_view() << std::endl; }, package);
					
					}
					
				}
				*/
			}

			void incoming_dummy_loop()
			{
				while (true)
				{
					auto _ = driver_.get_data();
				}
			}

		public:

			WinDivertClientVPNNetDriver_(QVPN::Core::QVPNClientSettings settings)
				: driver_(std::move(settings))
			{
			}

			void init_driver(const QVPN::Core::IPv4Address& addr)
			{
				logger_.set_prefix("WinDivert");
				vpn_connected_ = driver_.connect();
				if (vpn_connected_)
				{
					vpn_connected_ = driver_.init();
					return;
				}
				vpn_connected_ = driver_.try_reconnect();
				if (vpn_connected_)
					vpn_connected_ = driver_.init();
			}
			
			void add_outgoing_traffic_filter(Filter_t filter)
			{
				filters_out_.push_back(filter);
				calculate_outgoing_filters();
			}

			void add_incoming_traffic_filter(Filter_t filter)
			{
				filters_in_.push_back(filter);
				calculate_incoming_filters();
			}

			void start_capture_outgoing_traffic(const QVPN::Core::IPv4Address& adapter_addr, QVPN::Core::BaseTypes::ULong adapter_id)
			{
				//add_outgoing_traffic_filter(Filter::source(adapter_addr));
				apply_default_outgoing_filter();
				calculate_outgoing_filters();
				new_adapter_id = adapter_id;
				out_worker_ = std::thread([this, &adapter_addr]() {  speed_meter_.send_meter_start(); start_capture_outgoing_traffic_(adapter_addr); });
				//start_capture_outgoing_traffic_(adapter_addr);
			}

			void start_capture_incoming_traffic(const QVPN::Core::IPv4Address& adapter_addr)
			{
				//add_incoming_traffic_filter(Filter::dest(adapter_addr));
				apply_default_incoming_filter();
				calculate_incoming_filters();
				//dummy_worker_ = std::thread([this]() { incoming_dummy_loop(); });
				in_worker_ = std::thread([this, &adapter_addr]() { speed_meter_.recv_meter_start(); start_capture_incoming_traffic_(adapter_addr); });
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

		template <QVPN::Core::is_logger Logger>
		using QVPNClientDriver = QVPN::Core::QVPNClientDriver<QVPN::Core::BaseTypes::UByte*, QVPN::Core::NetAddr, QVPN::NetTools::QVPN_Socket, QVPN::NetTools::QVPNNetTools, Logger, QVPN::Core::QVPNClientWorkMode::CLIENT_VPN>;

		using WinDivertTrafficFilter = WinDivertTrafficFilter_<WinDivertTrafficFilterType>;

		template <QVPN::Core::is_logger Logger>
		using QVPNClientNetDriver = WinDivertClientVPNNetDriver_<WinDivertTrafficFilter, QVPNClientDriver<Logger>, Logger>;
	}


}