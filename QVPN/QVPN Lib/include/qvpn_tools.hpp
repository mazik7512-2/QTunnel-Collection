#pragma once
#include <unordered_map>
#include <ranges>
#include <random>
#include <ctime>
#include <algorithm>
#include <qvpn_structures.hpp>

namespace QVPN {

	namespace Core {

		namespace HttpTools
		{

			using HttpRequestType = QVPN::Core::DataStructures::HttpRequestType;
			using HttpConnectionType = QVPN::Core::DataStructures::HttpConnectionType;
			using HttpUserAgent = QVPN::Core::DataStructures::HttpUserAgent;
			using HttpVersion = QVPN::Core::DataStructures::HttpVersion;
			using HttpResponseStatus = QVPN::Core::DataStructures::HttpResponseStatus;
			using HttpContentType = QVPN::Core::DataStructures::HttpContentType;
			using QVPNCharset = QVPN::Core::DataStructures::QVPNCharset;
			using UInt = QVPN::Core::BaseTypes::UInt;


			inline std::unordered_map<std::string_view, HttpRequestType> request_types_ = {
				{"HEAD", HttpRequestType::HEAD}, {"GET", HttpRequestType::GET},
				{"POST", HttpRequestType::POST}, {"PUT", HttpRequestType::PUT},
				{"DELETE", HttpRequestType::DELETE_REQUEST}, {"CONNECT", HttpRequestType::CONNECT},
				{"OPTIONS", HttpRequestType::OPTIONS}, {"TRACE", HttpRequestType::TRACE}
			};

			inline std::unordered_map<std::string_view, HttpConnectionType> con_types_ = {
				{"keep-alive", HttpConnectionType::KEEP_ALIVE }, {"closed", HttpConnectionType::CLOSED }
			};

			inline std::unordered_map <std::string_view, HttpVersion> versions_ = {
				{"1.0", HttpVersion::HTTP1}, {"1.1", HttpVersion::HTTP1_1},
				{"2.0", HttpVersion::HTTP2}, {"3.0", HttpVersion::HTTP3}
			};

			inline std::unordered_map<std::string_view, HttpResponseStatus> statuses_ = {
				{"101", HttpResponseStatus::SWITCH_PROTOCOLS }, {"200", HttpResponseStatus::OK },
				{"201", HttpResponseStatus::CREATED }, {"301", HttpResponseStatus::MOVED_PERMANENTLY },
				{"400", HttpResponseStatus::BAD_REQUEST }, {"403", HttpResponseStatus::NOT_MODIFIED },
				{"404", HttpResponseStatus::NOT_FOUND }, {"500", HttpResponseStatus::INTERNAL_SERVER_ERROR },
				{"501", HttpResponseStatus::NOT_IMPLEMENTED }, {"505", HttpResponseStatus::HTTP_VERSION_NOT_SUPPORTED }
			};

			inline std::unordered_map<std::string_view, HttpContentType> content_types_ = {
				{"text/html", HttpContentType::TEXT_HTML}
			};

			inline std::unordered_map<std::string_view, QVPNCharset> charsets_ = {
				{"utf-8", QVPNCharset::UTF8}
			};

			HttpRequestType get_request_type_by_string(std::string_view request_type);// { return HttpRequestType(); }
			std::string str_to_upper(std::string_view::iterator begin, std::string_view::iterator end);// { return std::string(); }
			bool case_free_compare(char a, char b);// { return true; }
			int case_free_search(std::string_view source, std::string_view templ);// { return 0; }
			HttpConnectionType get_http_connection_type_by_string(std::string_view connection_type);// { return HttpConnectionType(); }
			std::string_view get_http_header_line(std::string_view http_data, std::string_view header_name);// { return std::string_view(); }
			std::string_view get_http_header_block(std::string_view http_data, std::string_view header_name);// { return std::string_view(); }
			HttpVersion get_http_version_by_string(std::string_view version);// { return HttpVersion(); }
			HttpResponseStatus get_http_status_by_string(std::string_view status);// { return HttpResponseStatus(); }
			HttpContentType get_http_content_type_by_string(std::string_view content);// { return HttpContentType(); }
			QVPNCharset get_http_charset_by_string(std::string_view charset);// { return QVPNCharset(); }


			template <class Iter>
				requires std::random_access_iterator<Iter>
			int find_http_header_end(Iter begin, Iter end)
			{
				constexpr UInt header_delimiter_min_size = 2;
				constexpr const UInt htpp_header_count = 4;
				constexpr std::array<std::string_view, htpp_header_count> http_header_ends = { "\r\n\r\n", "\n\n", "\r\r", "\r\n\n" };

				bool accept = false;
				int pos = 0;

				auto size = std::distance(begin, end);

				for (size_t i = 0; i < size - header_delimiter_min_size; i++)
				{
					for (size_t j = 0; j < http_header_ends.size(); j++)
					{
						accept = true;
						for (size_t k = 0; k < http_header_ends[j].size(); k++)
						{
							if (http_header_ends[j][k] != begin[i]) {
								accept = false;
								break;
							}
						}
					}

					if (accept) {
						pos = i;
					}
				}

				return pos;
			}

		};


		namespace TLSTools
		{

			using UInt = QVPN::Core::BaseTypes::UInt;
			using UByte = QVPN::Core::BaseTypes::UByte;

			std::pair<std::uniform_int_distribution<UInt>, std::mt19937> get_bytes_randomizer();

			template <std::ranges::random_access_range Cont, std::integral LengthSize>
			Cont bytes_generator(LengthSize length, UInt payload_offset)
			{
				auto [dist, gen] = get_bytes_randomizer();
				Cont obj_bytes;
				if constexpr (requires {obj_bytes.reserve(length); obj_bytes.resize(length); })
				{
					obj_bytes.reserve(length);
					obj_bytes.resize(length);
				}
				std::generate(obj_bytes.begin() + payload_offset, obj_bytes.end(), [&dist, &gen]() { return dist(gen); });
				return obj_bytes;
			}


			template <std::integral LengthSize>
			constexpr auto array32_bytes_generator = [](LengthSize length, UInt payload_offset) {
				return bytes_generator<std::array<UByte, 32>, LengthSize>(length, payload_offset);
			};

			template <std::integral LengthSize>
			constexpr auto vector_bytes_generator = [](LengthSize length, UInt payload_offset) {
				return bytes_generator<std::vector<UByte>, LengthSize>(length, payload_offset);
			};
		}


		namespace Tools
		{
			template <class Callable, class ... Args>
			decltype(auto) function_invoker(Callable F, Args&& ... args)
			{
				return F(std::forward<Args>(args)...);
			}

			template <class Callable, class ... Args>
			decltype(auto) function_invoker(Callable&& F, std::tuple<Args...>& tuple)
			{
				constexpr size_t tuple_args_count = std::tuple_size_v<std::tuple<Args...>>;
				return[&] <size_t ... it>(std::index_sequence<it...>) { return F(std::get<it>(tuple)...); }(std::make_index_sequence<tuple_args_count>{});
			}
		}
		
		class PreParser
		{
		private:

			using Ipv4TcpPacketView = QVPN::Core::DataStructures::Ipv4TcpPacket_View;
			using Ipv4UdpPacketView = QVPN::Core::DataStructures::Ipv4UdpPacket_View;
			using UByte = QVPN::Core::BaseTypes::UByte;

		private:

			template <std::random_access_iterator Iter>
			std::variant<Ipv4TcpPacketView, Ipv4UdpPacketView> pre_parse_ipv4(Iter begin, Iter end)
			{
				using TransportProtocols = QVPN::Core::DataStructures::TransportProtocols;
				//std::variant<Ipv4TcpPacketView, Ipv4UdpPacketView> ret;
				QVPN::Core::DataStructures::Ipv4Packet_View packet(begin, end);
				UByte proto = packet.get_ip_protocol();
				switch (proto) {
				case TransportProtocols::TCP:
					return Ipv4TcpPacketView(begin, end);
					break;
				case TransportProtocols::UDP:
					return Ipv4UdpPacketView(begin, end);
					break;
				default:
					break;
				}
				//return ret;
			}

		public:

			template <std::random_access_iterator Iter>
			std::variant<Ipv4TcpPacketView, Ipv4UdpPacketView> pre_parse(Iter begin, Iter end)
			{
				using NetProtocols = QVPN::Core::DataStructures::NetProtocols;
				//std::variant<Ipv4TcpPacketView, Ipv4UdpPacketView> ret;
				UByte ip_ver = begin[0] >> 4 & 0xF;
				switch (ip_ver) {
				case NetProtocols::IPv4:
					return pre_parse_ipv4<Iter>(begin, end);
					break;
				case NetProtocols::IPv6:
					break;
				default:
					break;
				}
				//return ret;
			}
		};

	}

}