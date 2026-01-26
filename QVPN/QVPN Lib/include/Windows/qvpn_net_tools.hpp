#pragma once

#include <qvpn_lib.hpp>

#include <winsock2.h>     
#include <ws2ipdef.h>
#include <variant>
#include <type_traits>
#include <ws2tcpip.h>

#include <iostream>
#pragma comment(lib, "ws2_32.lib")


namespace std
{
	// for socket family class
	template<>
	struct hash<QVPN::Core::NetProtocol> {
		size_t operator()(const QVPN::Core::NetProtocol& data) const {
			return hash<int>()(data);
		}

	};
}

namespace QVPN {

	namespace NetTools {

		using UByte = QVPN::Core::BaseTypes::UByte;
		using UShort = QVPN::Core::BaseTypes::UShort;
		using QVPNSocketData = QVPN::Core::QVPNSocketData;

		class QVPN_Socket;

		class QVPNMetaSocketData
		{
			std::unordered_map<QVPN::Core::NetProtocol, int> families_ = { {QVPN::Core::NetProtocol::IPv4, AF_INET}, {QVPN::Core::NetProtocol::IPv6, AF_INET6} };
			std::unordered_map<QVPN::Core::TransportProtocol, int> raw_types_ = { {QVPN::Core::TransportProtocol::TCP, SOCK_RAW}, {QVPN::Core::TransportProtocol::UDP, SOCK_RAW} };
			std::unordered_map<QVPN::Core::TransportProtocol, int> types_ = { {QVPN::Core::TransportProtocol::TCP, SOCK_STREAM }, {QVPN::Core::TransportProtocol::UDP, SOCK_DGRAM } };
			std::unordered_map<QVPN::Core::TransportProtocol, int> protos_ = { {QVPN::Core::TransportProtocol::TCP, IPPROTO_TCP}, {QVPN::Core::TransportProtocol::UDP, IPPROTO_UDP} };
		public:

			using SockParam = int;

			SockParam get_socket_family(QVPN::Core::NetProtocol net_proto);
			SockParam get_socket_type(QVPN::Core::TransportProtocol t_proto);
			SockParam get_socket_proto(QVPN::Core::TransportProtocol t_proto);

			SockParam get_raw_socket_type(QVPN::Core::TransportProtocol t_proto);

		};

		class QVPNNetTools
		{
		public:

			static QVPN::NetTools::QVPN_Socket create_socket(QVPN::Core::NetProtocol net_proto, QVPN::Core::TransportProtocol t_proto);
			static QVPN::NetTools::QVPN_Socket create_raw_socket(QVPN::Core::NetProtocol net_proto, QVPN::Core::TransportProtocol t_proto);
		};


		enum SocketMod
		{
			SERVER_MOD = 0,
			CLIENT_MOD = 1,
			UNDEFINED = 2
		};

		namespace details
		{
			// inline - no odr usage
			inline QVPN::Core::NetData qvpn_connect_(SOCKET& socket, const QVPN::Core::IPv4Address& addr, const UShort port)
			{
				struct sockaddr_in serverAddr {};
				int addr_len = sizeof(serverAddr);
				serverAddr.sin_family = AF_INET;
				serverAddr.sin_port = htons(port);
				serverAddr.sin_addr.S_un.S_addr = htonl(addr.to_uint());//std::visit([](const auto& address) { return address.to_uint(); }, addr);

				int res = connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
				int err = 0;
				if (res == SOCKET_ERROR)
					err = WSAGetLastError();

				getsockname(socket, (sockaddr*)&serverAddr, &addr_len);

				QVPN::Core::NetAddr net_addr((UByte*)&serverAddr.sin_addr.S_un.S_un_b, (UByte*)&serverAddr.sin_addr.S_un.S_un_b + addr_len);

				bool s = (res == 0) ? true : false;
				
					
				return QVPN::Core::NetData{ s , err, net_addr, port };
			}

			inline QVPN::Core::NetData qvpn_connect_(SOCKET& socket, const QVPN::Core::IPv6Address& addr, const UShort port)
			{
				struct sockaddr_in6 serverAddr {};
				int addr_len = sizeof(serverAddr);
				serverAddr.sin6_family = AF_INET6;
				serverAddr.sin6_port = htons(port);
				//serverAddr.sin6_addr.u.Byte = addr.to_bytes();//std::visit([](const auto& address) { return address.to_bytes(); }, addr);
				auto bytes = addr.to_bytes();
				std::memcpy(&serverAddr.sin6_addr.u.Byte, bytes.data(), bytes.size());
				int res = connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));

				getsockname(socket, (sockaddr*)&serverAddr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)&serverAddr.sin6_addr.u.Byte, (UByte*)&serverAddr.sin6_addr.u.Byte + addr_len);

				bool s = (res == 0) ? true : false;
				int err = 0;
				if (!s)
					err = WSAGetLastError();
				return QVPN::Core::NetData{ s , err, net_addr, port };
			}


			inline QVPN::Core::NetData qvpn_connect_(SOCKET& socket, const QVPN::Core::NetAddr& addr, const UShort port)
			{
				auto addr_family = addr.get_addr_family();
				switch (addr_family)
				{
				case QVPN::Core::NetProtocol::IPv4:
					return qvpn_connect_(socket, addr.to_ipv4(), port);
				case QVPN::Core::NetProtocol::IPv6:
					return qvpn_connect_(socket, addr.to_ipv6(), port);
				default:
					return QVPN::Core::NetData{ false, 0 };
				}
				
			}


			inline QVPN::Core::NetData qvpn_bind_(SOCKET& socket, const QVPN::Core::IPv4Address& addr, const UShort port)
			{
				struct sockaddr_in serverAddr {};
				int addr_len = 4;
				serverAddr.sin_family = AF_INET;
				serverAddr.sin_port = htons(port);
				serverAddr.sin_addr.S_un.S_addr = htonl(addr.to_uint());//std::visit([](const auto& address) { return address.to_uint(); }, addr);
				int res = bind(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));

				getsockname(socket, (sockaddr*)&serverAddr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)&serverAddr.sin_addr.S_un.S_un_b, (UByte*)&serverAddr.sin_addr.S_un.S_un_b + addr_len);

				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetData{ s , res, net_addr, port };
			}

			inline QVPN::Core::NetData qvpn_bind_(SOCKET& socket, const QVPN::Core::IPv6Address& addr, const UShort port)
			{
				struct sockaddr_in6 serverAddr {};
				int addr_len = sizeof(serverAddr);
				serverAddr.sin6_family = AF_INET6;
				serverAddr.sin6_port = htons(port);
				//serverAddr.sin6_addr.u.Byte = addr.to_bytes();//std::visit([](const auto& address) { return address.to_bytes(); }, addr);
				auto bytes = addr.to_bytes();
				std::memcpy(&serverAddr.sin6_addr.u.Byte, bytes.data(), bytes.size());
				int res = bind(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));

				getsockname(socket, (sockaddr*)&serverAddr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)&serverAddr.sin6_addr.u.Byte, (UByte*)&serverAddr.sin6_addr.u.Byte + addr_len);

				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetData{ s , res, net_addr, port };
			}

			inline QVPN::Core::NetData qvpn_bind_(SOCKET& socket, const QVPN::Core::NetAddr& addr, const UShort port)
			{
				auto addr_family = addr.get_addr_family();
				switch (addr_family)
				{
				case QVPN::Core::NetProtocol::IPv4:
					return qvpn_bind_(socket, addr.to_ipv4(), port);
				case QVPN::Core::NetProtocol::IPv6:
					return qvpn_bind_(socket, addr.to_ipv6(), port);
				default:
					return QVPN::Core::NetData{ false, 0 };
				}
			}

		}


		namespace details
		{
			
			using TransportProtocol = QVPN::Core::TransportProtocol;
			using NetProtocol = QVPN::Core::NetProtocol;

			
			template <QVPN::Core::NetProtocol NetP, QVPN::Core::is_addr Addr, class Socket>
				requires QVPN::Core::is_socket<Socket, Addr>
			struct SocketAccept
			{
				Socket operator()(SOCKET& socket, NetProtocol net_proto, TransportProtocol t_proto)
				{
					return Socket{};
				}
			};


			template <class Socket>
			requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr>
			struct SocketAccept<NetProtocol::IPv4, QVPN::Core::NetAddr, Socket>
			{
				Socket operator()(SOCKET& socket, NetProtocol net_proto, TransportProtocol t_proto)
				{
					sockaddr_in sock_addr{};
					int addr_len = sizeof(sock_addr);

					struct sockaddr_in clientAddr {};
					int clientAddrLen = sizeof(clientAddr);
					auto sock = ::accept(socket, (sockaddr*)&clientAddr, &clientAddrLen);

					getsockname(sock, (sockaddr*)&sock_addr, &addr_len);
					getpeername(sock, (sockaddr*)&clientAddr, &clientAddrLen);

					QVPN::Core::NetAddr net_addr((UByte*)&sock_addr.sin_addr.S_un.S_un_b, (UByte*)&sock_addr.sin_addr.S_un.S_un_b + 4);

					QVPN::Core::NetAddr addr((UByte*)&clientAddr.sin_addr.S_un.S_un_b, (UByte*)&clientAddr.sin_addr.S_un.S_un_b + 4);
					UShort port = clientAddr.sin_port;
					return Socket(sock, addr, port, net_addr, ntohs(sock_addr.sin_port), SERVER_MOD, t_proto);
				}
			};


			template <class Socket>
			requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr>
			struct SocketAccept<NetProtocol::IPv6, QVPN::Core::NetAddr, Socket>
			{
				Socket operator()(SOCKET& socket, NetProtocol net_proto, TransportProtocol t_proto)
				{
					// TODO: не уверен что будет работать
					sockaddr_in6 sock_addr{};
					int addr_len = sizeof(sock_addr);

					struct sockaddr_in6 clientAddr {};
					int clientAddrLen = sizeof(clientAddr);
					auto sock = ::accept(socket, (sockaddr*)&clientAddr, &clientAddrLen);

					getsockname(sock, (sockaddr*)&sock_addr, &addr_len);
					getpeername(sock, (sockaddr*)&clientAddr, &clientAddrLen);

					QVPN::Core::NetAddr net_addr((UByte*)&sock_addr.sin6_addr.u.Byte, (UByte*)&sock_addr.sin6_addr.u.Byte + addr_len);

					QVPN::Core::NetAddr addr((UByte*)&clientAddr.sin6_addr.u.Byte, (UByte*)&clientAddr.sin6_addr.u.Byte + addr_len);
					UShort port = clientAddr.sin6_port;
					return Socket(sock, addr, port, net_addr, ntohs(sock_addr.sin6_port), SERVER_MOD, t_proto);
				}
			};

			// Должно уместить все (и ipv4, и ipv6)
			template <class Socket>
			requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr>
			struct SocketAccept<NetProtocol::NET_UNDEFINED, QVPN::Core::NetAddr, Socket>
			{
				Socket operator()(SOCKET& socket, NetProtocol net_proto, TransportProtocol t_proto)
				{
					switch (net_proto)
					{
					case NetProtocol::IPv4:
						return SocketAccept<NetProtocol::IPv4, QVPN::Core::NetAddr, Socket>{}(socket, net_proto, t_proto);
					case NetProtocol::IPv6:
						return SocketAccept<NetProtocol::IPv6, QVPN::Core::NetAddr, Socket>{}(socket, net_proto, t_proto);
					}
				}
			};

		}


		class QVPN_Socket
		{
		public:
			static constexpr int buffer_size = 1 << 16;

		private:
			SOCKET socket_;
			WSADATA wsa_data_{};

			QVPNSocketData socket_data_{};
			int s_type_ = -1;

			SocketMod s_mod_ = UNDEFINED;

			using TransportProtocol = QVPN::Core::TransportProtocol;
			using QVPNSocketSettings = QVPN::Core::QVPNSocketSettings;
			using ReceiveData = QVPN::Core::ReceiveData;
		public:

			QVPN_Socket();

			QVPN_Socket(int sock_family, int sock_type, int sock_proto);

			template <class ... Args>
			QVPN_Socket(Args&& ... args)
			{
				int result = WSAStartup(MAKEWORD(2, 2), &wsa_data_);
				if (result == 0)
				{
					socket_ = socket(std::forward<Args>(args)...);
					socket_data_.remote_port = 0;
					socket_data_.local_port = 0;
					s_mod_ = UNDEFINED;
				}
			}
			
			QVPN_Socket(const QVPN_Socket& other) noexcept;
			QVPN_Socket& operator=(const QVPN_Socket& other) noexcept;
			QVPN_Socket(QVPN_Socket&& other) noexcept;
			QVPN_Socket& operator=(QVPN_Socket&& other) noexcept;

			QVPN_Socket(SOCKET socket, QVPN::Core::IPv4Address remote_addr, UShort remote_port, QVPN::Core::IPv4Address local_addr, UShort local_port, SocketMod s_mod, TransportProtocol transport_proto);
			QVPN_Socket(SOCKET socket, QVPN::Core::IPv6Address remote_addr, UShort remote_port, QVPN::Core::IPv6Address local_addr, UShort local_port, SocketMod s_mod, TransportProtocol transport_proto);
			QVPN_Socket(SOCKET socket, QVPN::Core::NetAddr remote_addr, UShort remote_port, QVPN::Core::NetAddr local_addr, UShort local_port, SocketMod s_mod, TransportProtocol transport_proto);

			template<class ... Args>
			void create_socket_by_args(Args&& ... args)
			{
				socket_ = socket(std::forward<Args>(args)...);
			}

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus connect(const Addr& addr, const UShort port)
			{
				if (s_mod_ == SERVER_MOD)
					return QVPN::Core::NetStatus{ false, 0 };
				QVPN::Core::NetStatus status{};
				QVPN::Core::NetData data{};
				status.success = false;

				data = QVPN::NetTools::details::qvpn_connect_(socket_, addr, port);
				status.status = data.status;
				status.success = data.success;

				if (status.success) {
					socket_data_.remote_port = port;
					socket_data_.remote_addr = addr;
					socket_data_.local_port = data.port;
					socket_data_.local_addr = data.addr;
					s_mod_ = CLIENT_MOD;
				}
				return status;
			}
			
			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus reconnect(const Addr& addr, const UShort port)
			{
				if (check_connected())
				{
					shutdown();
					close_socket();
					QVPNMetaSocketData meta{};
					if (s_type_ == SOCK_RAW)
						socket_ = socket(meta.get_socket_family(socket_data_.local_addr.get_addr_family()), meta.get_raw_socket_type(socket_data_.transport_proto), meta.get_socket_proto(socket_data_.transport_proto));
					else
						socket_ = socket(meta.get_socket_family(socket_data_.local_addr.get_addr_family()), meta.get_socket_type(socket_data_.transport_proto), meta.get_socket_proto(socket_data_.transport_proto));
				}
				return connect<Addr>(addr, port);
			}

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus bind(const Addr& addr, const UShort port)
			{
				if (s_mod_ == CLIENT_MOD)
					return QVPN::Core::NetStatus{ false, 0 };
				QVPN::Core::NetStatus status{};
				QVPN::Core::NetData data{};
				
				data = QVPN::NetTools::details::qvpn_bind_(socket_, addr, port);

				status.status = data.status;
				status.success = data.success;

				if (status.success) {
					socket_data_.remote_port = port;
					socket_data_.remote_addr = addr;
					socket_data_.local_port = data.port;
					socket_data_.local_addr = data.addr;
					s_mod_ = SERVER_MOD;
				}

				return status;
			}

			template <QVPN::Core::is_addr Addr>
			QVPN_Socket accept()
			{
				return QVPN::NetTools::details::SocketAccept<QVPN::Core::NetProtocol::NET_UNDEFINED, Addr, QVPN_Socket>{}(socket_, socket_data_.local_addr.get_addr_family(), socket_data_.transport_proto);
			}

			QVPN::Core::NetStatus listen(int con_limit = SOMAXCONN);

			QVPN::Core::NetStatus send(const UByte* begin, const UByte* end, int flags = 0);

			ReceiveData receive(int flags = 0);

			QVPN::Core::NetStatus disconnect() const;

			bool check_connected() const;

			void disconnect_if_connected() const;

			QVPN::Core::NetStatus shutdown();

			void close_socket() const;

			const QVPN::Core::NetAddr& get_local_addr() const
			{
				return socket_data_.local_addr;
			}

			UShort get_local_port() const
			{
				return socket_data_.local_port;
			}

			const QVPN::Core::NetAddr& get_remote_addr() const
			{
				return socket_data_.remote_addr;
			}

			UShort get_remote_port() const
			{
				return socket_data_.remote_port;
			}

			TransportProtocol get_transport_protocol() const
			{
				return socket_data_.transport_proto;
			}

			void apply_settings(const QVPNSocketSettings& settings)
			{
				char optval = static_cast<char>(settings.ip_header());
				int optlen = sizeof(optval);
				setsockopt(socket_, IPPROTO_IP, IP_HDRINCL, &optval, optlen);
			}

		};


	}

}
