#pragma once

#include <qvpn_lib.hpp>

#include <winsock2.h>     
#include <ws2ipdef.h>
#include <variant>
#include <type_traits>
#include <ws2tcpip.h>
#include <qvpn_socket_filters.hpp>

#include <iostream>
#include <utility>
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
		using UInt = QVPN::Core::BaseTypes::UInt;
		using ULong = QVPN::Core::BaseTypes::ULong;
		using QVPNSocketData = QVPN::Core::QVPNSocketData;



		class QVPN_Socket;
		class QVPN_RawSocket;

		class QVPNMetaSocketData
		{
			std::unordered_map<QVPN::Core::NetProtocol, int> families_ = { {QVPN::Core::NetProtocol::IPv4, AF_INET}, {QVPN::Core::NetProtocol::IPv6, AF_INET6} };
			std::unordered_map<QVPN::Core::TransportProtocol, int> raw_types_ = { {QVPN::Core::TransportProtocol::TCP, SOCK_RAW}, {QVPN::Core::TransportProtocol::UDP, SOCK_RAW} };
			std::unordered_map<QVPN::Core::TransportProtocol, int> types_ = { {QVPN::Core::TransportProtocol::TCP, SOCK_STREAM }, {QVPN::Core::TransportProtocol::UDP, SOCK_DGRAM } };
			std::unordered_map<QVPN::Core::TransportProtocol, int> protos_ = { {QVPN::Core::TransportProtocol::TCP, IPPROTO_TCP}, {QVPN::Core::TransportProtocol::UDP, IPPROTO_UDP } };
			std::unordered_map<QVPN::Core::TransportProtocol, int> raw_protos_ = { {QVPN::Core::TransportProtocol::TCP, IPPROTO_TCP}, {QVPN::Core::TransportProtocol::UDP, IPPROTO_UDP } };
		public:

			using SockParam = int;

			SockParam get_socket_family(QVPN::Core::NetProtocol net_proto);
			SockParam get_socket_type(QVPN::Core::TransportProtocol t_proto);
			SockParam get_socket_proto(QVPN::Core::TransportProtocol t_proto);

			SockParam get_raw_socket_type(QVPN::Core::TransportProtocol t_proto);
			SockParam get_raw_socket_proto(QVPN::Core::TransportProtocol t_proto);

		};

		class QVPNNetTools
		{
		public:

			using Socket = QVPN_Socket;
			using RawSocket = QVPN_RawSocket;
			using SocketFilter = QVPN_SocketFilter;

			static QVPN::NetTools::QVPNNetTools::Socket create_socket(QVPN::Core::NetProtocol net_proto, QVPN::Core::TransportProtocol t_proto);
			static QVPN::NetTools::QVPNNetTools::RawSocket create_raw_socket(QVPN::Core::NetProtocol net_proto, QVPN::Core::TransportProtocol t_proto);
			static SocketFilter create_socket_filter(const QVPNSocketData& s_data);
			static SocketFilter create_socket_filter(const QVPN::Core::QVPNServerSocketData& s_data);

			static UShort hton(UShort num);
			static UShort ntoh(UShort num);

			static UInt hton(UInt num);
			static UInt ntoh(UInt num);

			static ULong hton(ULong num);
			static ULong ntoh(ULong num);

		};


		namespace details
		{
			// inline - no odr usage
			inline QVPN::Core::NetData qvpn_connect_(SOCKET& socket, const QVPN::Core::IPv4Address& addr, const UShort port)
			{
				struct sockaddr_in serverAddr {};
				memset(&serverAddr, 0, sizeof(serverAddr));
				int addr_len = sizeof(serverAddr);
				serverAddr.sin_family = AF_INET;
				serverAddr.sin_port = htons(port);
				serverAddr.sin_addr.S_un.S_addr = htonl(addr.to_uint());

				int res = connect(socket, (sockaddr*)&serverAddr, addr_len);
				int err = 0;
				if (res == SOCKET_ERROR)
					err = WSAGetLastError();

				sockaddr_in localAddr{};
				int localAddrLen = sizeof(localAddr);

				getsockname(socket, (sockaddr*)&localAddr, &localAddrLen);

				QVPN::Core::NetAddr net_addr((UByte*)&localAddr.sin_addr.S_un.S_un_b, (UByte*)&localAddr.sin_addr.S_un.S_un_b + localAddrLen);

				bool s = (res == 0) ? true : false;
				
					
				return QVPN::Core::NetData{ s , err, net_addr, ntohs(localAddr.sin_port) };
			}

			inline QVPN::Core::NetData qvpn_connect_(SOCKET& socket, const QVPN::Core::IPv6Address& addr, const UShort port)
			{
				struct sockaddr_in6 serverAddr {};
				memset(&serverAddr, 0, sizeof(serverAddr));
				int addr_len = sizeof(serverAddr);
				serverAddr.sin6_family = AF_INET6;
				serverAddr.sin6_port = htons(port);
				auto bytes = addr.to_bytes();
				std::memcpy(&serverAddr.sin6_addr.u.Byte, bytes.data(), bytes.size());
				int res = connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));

				sockaddr_in6 localAddr{};
				int localAddrLen = sizeof(localAddr);

				getsockname(socket, (sockaddr*)&localAddr, &localAddrLen);

				QVPN::Core::NetAddr net_addr((UByte*)&localAddr.sin6_addr.u.Byte, (UByte*)&localAddr.sin6_addr.u.Byte + localAddrLen);

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
				int err = 0;
				struct sockaddr_in serverAddr {};
				int addr_len = 4;
				serverAddr.sin_family = AF_INET;
				serverAddr.sin_port = htons(port);
				serverAddr.sin_addr.S_un.S_addr = htonl(addr.to_uint());
				int res = bind(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
				if (res == SOCKET_ERROR)
					err = WSAGetLastError();
				getsockname(socket, (sockaddr*)&serverAddr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)&serverAddr.sin_addr.S_un.S_un_b, (UByte*)&serverAddr.sin_addr.S_un.S_un_b + addr_len);

				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetData{ s , err, net_addr, port };
			}

			inline QVPN::Core::NetData qvpn_bind_(SOCKET& socket, const QVPN::Core::IPv6Address& addr, const UShort port)
			{
				int err = 0;
				struct sockaddr_in6 serverAddr {};
				int addr_len = sizeof(serverAddr);
				serverAddr.sin6_family = AF_INET6;
				serverAddr.sin6_port = htons(port);
				auto bytes = addr.to_bytes();
				std::memcpy(&serverAddr.sin6_addr.u.Byte, bytes.data(), bytes.size());
				int res = bind(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
				if (res == SOCKET_ERROR)
					err = WSAGetLastError();
				getsockname(socket, (sockaddr*)&serverAddr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)&serverAddr.sin6_addr.u.Byte, (UByte*)&serverAddr.sin6_addr.u.Byte + addr_len);

				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetData{ s , err, net_addr, port };
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
				requires QVPN::Core::is_socket<Socket, Addr> || QVPN::Core::is_raw_socket<Socket, Addr, typename Socket::SocketFilter>
			struct SocketAccept
			{
				Socket operator()(SOCKET& socket, NetProtocol net_proto, TransportProtocol t_proto)
				{
					return Socket{};
				}
			};


			template <class Socket>
			requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr> || QVPN::Core::is_raw_socket<Socket, QVPN::Core::NetAddr, typename Socket::SocketFilter>
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
					return Socket(sock, addr, port, net_addr, ntohs(sock_addr.sin_port), t_proto);
				}
			};


			template <class Socket>
			requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr> || QVPN::Core::is_raw_socket<Socket, QVPN::Core::NetAddr, typename Socket::SocketFilter>
			struct SocketAccept<NetProtocol::IPv6, QVPN::Core::NetAddr, Socket>
			{
				Socket operator()(SOCKET& socket, NetProtocol net_proto, TransportProtocol t_proto)
				{
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
					return Socket(sock, addr, port, net_addr, ntohs(sock_addr.sin6_port), t_proto);
				}
			};

			// Должно уместить все (и ipv4, и ipv6)
			template <class Socket>
			requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr> || QVPN::Core::is_raw_socket<Socket, QVPN::Core::NetAddr, typename Socket::SocketFilter>
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
					return Socket();
				}
			};



			// Send to
			template <NetProtocol Net, QVPN::Core::is_addr Addr, class Socket>
				requires QVPN::Core::is_socket<Socket, Addr> || QVPN::Core::is_raw_socket<Socket, Addr, typename Socket::SocketFilter>
			struct SocketSendTo
			{
				template <std::random_access_iterator Iter>
				QVPN::Core::NetStatus operator()(SOCKET& socket, NetProtocol net_proto, const Addr& addr, const UShort port, Iter begin, Iter end)
				{
					return QVPN::Core::NetStatus{};
				}
			};

			template <class Socket>
				requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr> || QVPN::Core::is_raw_socket<Socket, QVPN::Core::NetAddr, typename Socket::SocketFilter>
			struct SocketSendTo<NetProtocol::IPv4, QVPN::Core::NetAddr, Socket>
			{
				template <std::random_access_iterator Iter>
				QVPN::Core::NetStatus operator()(SOCKET& socket, NetProtocol net_proto, const QVPN::Core::NetAddr& addr, const UShort port, Iter begin, Iter end)
				{
					bool s = true;
					sockaddr_in sock_addr{};
					sock_addr.sin_family = AF_INET;
					sock_addr.sin_addr.S_un.S_addr = htonl(addr.to_uint());
					sock_addr.sin_port = htons(port);
					int addr_len = sizeof(sock_addr);
					int err = 0;
					auto size = std::distance(begin, end);
					auto sock = ::sendto(socket, reinterpret_cast<const char*>(begin), size, 0, (sockaddr*)&sock_addr, addr_len);
					if (sock == SOCKET_ERROR)
					{
						err = WSAGetLastError();
						s = false;
					}
					return QVPN::Core::NetStatus{ s, err };
				}
			};

			template <class Socket>
				requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr> || QVPN::Core::is_raw_socket<Socket, QVPN::Core::NetAddr, typename Socket::SocketFilter>
			struct SocketSendTo<NetProtocol::IPv6, QVPN::Core::NetAddr, Socket>
			{
				template <std::random_access_iterator Iter>
				QVPN::Core::NetStatus operator()(SOCKET& socket, NetProtocol net_proto, const QVPN::Core::NetAddr& addr, const UShort port, Iter begin, Iter end)
				{
					bool s = true;
					sockaddr_in6 sock_addr{};
					auto addr_bytes = addr.to_bytes();
					memcpy(sock_addr.sin6_addr.u.Byte, addr_bytes.data(), addr_bytes.size());
					sock_addr.sin6_family = AF_INET6;
					sock_addr.sin6_port = htons(port);
					int addr_len = sizeof(sock_addr);
					int err = 0;
					auto size = std::distance(begin, end);
					auto sock = ::sendto(socket, reinterpret_cast<const char*>(begin), size, 0, (sockaddr*)&sock_addr, addr_len);
					if (sock == SOCKET_ERROR)
					{
						err = WSAGetLastError();
						s = false;
					}
					return QVPN::Core::NetStatus{ s, err };
				}
			};

			// Должно уместить все (и ipv4, и ipv6)
			template <class Socket>
				requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr> || QVPN::Core::is_raw_socket<Socket, QVPN::Core::NetAddr, typename Socket::SocketFilter>
			struct SocketSendTo<NetProtocol::NET_UNDEFINED, QVPN::Core::NetAddr, Socket>
			{
				template <std::random_access_iterator Iter>
				QVPN::Core::NetStatus operator()(SOCKET& socket, NetProtocol net_proto, const QVPN::Core::NetAddr& addr, const UShort port, Iter begin, Iter end)
				{
					switch (net_proto)
					{
					case NetProtocol::IPv4:
						return SocketSendTo<NetProtocol::IPv4, QVPN::Core::NetAddr, Socket>{}(socket, net_proto, addr, port, begin, end);
					case NetProtocol::IPv6:
						return SocketSendTo<NetProtocol::IPv6, QVPN::Core::NetAddr, Socket>{}(socket, net_proto, addr, port, begin, end);
					}
					return QVPN::Core::NetStatus{};
				}
			};


			// Recv from
			template <NetProtocol Net, QVPN::Core::is_addr Addr, class Socket>
				requires QVPN::Core::is_socket<Socket, Addr> || QVPN::Core::is_raw_socket<Socket, Addr, typename Socket::SocketFilter>
			struct SocketRecvFrom
			{
				QVPN::Core::ReceiveData operator()(SOCKET& socket, NetProtocol net_proto, const Addr& addr, const UShort port)
				{
					return QVPN::Core::ReceiveData{};
				}
			};

			template <class Socket>
				requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr> || QVPN::Core::is_raw_socket<Socket, QVPN::Core::NetAddr, typename Socket::SocketFilter>
			struct SocketRecvFrom<NetProtocol::IPv4, QVPN::Core::NetAddr, Socket>
			{
				QVPN::Core::ReceiveData operator()(SOCKET& socket, NetProtocol net_proto, const QVPN::Core::NetAddr& addr, const UShort port)
				{
					bool s = true;
					std::array<UByte, QVPN::Core::ReceiveData::buffer_size> data{};
					sockaddr_in sock_addr{};
					// sock_addr - out param
					int addr_len = sizeof(sock_addr);
					int err = 0;
					auto sock = ::recvfrom(socket, reinterpret_cast<char*>(data.data()), data.size(), 0, (sockaddr*)&sock_addr, &addr_len);
					if (sock == SOCKET_ERROR)
					{
						err = WSAGetLastError();
						s = false;
					}
					QVPN::Core::NetStatus status{ s, err };
					return QVPN::Core::ReceiveData{ status, sock, std::move(data)};
				}
			};

			template <class Socket>
				requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr> || QVPN::Core::is_raw_socket<Socket, QVPN::Core::NetAddr, typename Socket::SocketFilter>
			struct SocketRecvFrom<NetProtocol::IPv6, QVPN::Core::NetAddr, Socket>
			{
				QVPN::Core::ReceiveData operator()(SOCKET& socket, NetProtocol net_proto, const QVPN::Core::NetAddr& addr, const UShort port)
				{
					bool s = true;
					std::array<UByte, QVPN::Core::ReceiveData::buffer_size> data{};
					sockaddr_in6 sock_addr{};
					// sock_addr - out param
					int addr_len = sizeof(sock_addr);
					int err = 0;
					auto sock = ::recvfrom(socket, reinterpret_cast<char*>(data.data()), data.size(), 0, (sockaddr*)&sock_addr, &addr_len);
					if (sock == SOCKET_ERROR)
					{
						err = WSAGetLastError();
						s = false;
					}
					QVPN::Core::NetStatus status{s, err };
					return QVPN::Core::ReceiveData{ status, sock, std::move(data) };
				}
			};

			// Должно уместить все (и ipv4, и ipv6)
			template <class Socket>
				requires QVPN::Core::is_socket<Socket, QVPN::Core::NetAddr> || QVPN::Core::is_raw_socket<Socket, QVPN::Core::NetAddr, typename Socket::SocketFilter>
			struct SocketRecvFrom<NetProtocol::NET_UNDEFINED, QVPN::Core::NetAddr, Socket>
			{
				QVPN::Core::ReceiveData operator()(SOCKET& socket, NetProtocol net_proto, const QVPN::Core::NetAddr& addr, const UShort port)
				{
					switch (net_proto)
					{
					case NetProtocol::IPv4:
						return SocketRecvFrom<NetProtocol::IPv4, QVPN::Core::NetAddr, Socket>{}(socket, net_proto, addr, port);
					case NetProtocol::IPv6:
						return SocketRecvFrom<NetProtocol::IPv6, QVPN::Core::NetAddr, Socket>{}(socket, net_proto, addr, port);
					}
					return QVPN::Core::ReceiveData{};
				}
			};

		}


		class QVPN_Socket
		{
		public:
			static constexpr int buffer_size = 1 << 16;
			using SocketFilter = QVPN_SocketFilter;

		private:
			SOCKET socket_;
			WSADATA wsa_data_{};

			QVPNSocketData socket_data_{};

			using TransportProtocol = QVPN::Core::TransportProtocol;
			using QVPNSocketSettings = QVPN::Core::QVPNSocketSettings;
			using ReceiveData = QVPN::Core::ReceiveData;

			using SafeReceiveSignal = QVPN::Core::SafeReceiveSignal;

			template <class AppLevelProtoTemplate>
			using SafeReceiveData = QVPN::Core::SafeReceiveData<AppLevelProtoTemplate>;

		public:

			QVPN_Socket();

			QVPN_Socket(int sock_family, int sock_type, int sock_proto);

			QVPN_Socket(const QVPN_Socket& other) noexcept;
			QVPN_Socket& operator=(const QVPN_Socket& other) noexcept;
			QVPN_Socket(QVPN_Socket&& other) noexcept;
			QVPN_Socket& operator=(QVPN_Socket&& other) noexcept;

			QVPN_Socket(SOCKET socket, QVPN::Core::IPv4Address remote_addr, UShort remote_port, QVPN::Core::IPv4Address local_addr, UShort local_port, TransportProtocol transport_proto);
			QVPN_Socket(SOCKET socket, QVPN::Core::IPv6Address remote_addr, UShort remote_port, QVPN::Core::IPv6Address local_addr, UShort local_port, TransportProtocol transport_proto);
			QVPN_Socket(SOCKET socket, QVPN::Core::NetAddr remote_addr, UShort remote_port, QVPN::Core::NetAddr local_addr, UShort local_port, TransportProtocol transport_proto);

			template<class ... Args>
			void create_socket_by_args(Args&& ... args)
			{
				socket_ = socket(std::forward<Args>(args)...);
			}

			bool is_valid() const;

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus connect(const Addr& addr, const UShort port)
			{
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
					socket_ = socket(meta.get_socket_family(socket_data_.local_addr.get_addr_family()), meta.get_socket_type(socket_data_.transport_proto), meta.get_socket_proto(socket_data_.transport_proto));
				}
				return connect<Addr>(addr, port);
			}

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus bind(const Addr& addr, const UShort port)
			{
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

				int timeout = settings.receive_timeout_ms();
				optlen = sizeof(timeout);
				setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), optlen);
			}

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus send_to(const Addr& addr, const UShort port, const UByte* begin, const UByte* end)
			{
				return NetTools::details::SocketSendTo<QVPN::Core::NetProtocol::NET_UNDEFINED, Addr, QVPN_Socket>{}(socket_, addr.get_addr_family(), addr, port, begin, end);
			}

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::ReceiveData recv_from(const Addr& addr, const UShort port)
			{
				return NetTools::details::SocketRecvFrom<QVPN::Core::NetProtocol::NET_UNDEFINED, Addr, QVPN_Socket>{}(socket_, addr.get_addr_family(), addr, port);
			}

			// Return full app level data
			template <QVPN::Core::is_proto_template AppLevelProtoTemplate>
			SafeReceiveData<AppLevelProtoTemplate> safe_recv(int flags = 0)
			{
				int num_tries = 20;
				SafeReceiveData<AppLevelProtoTemplate> sf_data{};
				SafeReceiveSignal signal = SafeReceiveSignal::SFR_NO_DATA;
				while (signal != SafeReceiveSignal::SFR_FULL_DATA || signal == SafeReceiveSignal::SFR_ERROR || num_tries <= 0)
				{
					auto data = receive(flags);
					sf_data.set_status(data.status);
					if (!data.status.success)
					{
						num_tries--;
						continue;
					}
					signal = sf_data.add_objects_and_validate(signal, data.data.data(), data.data.data() + data.size);
				}

				return sf_data;
			}

		};


		class QVPN_RawSocket
		{
		public:
			static constexpr int buffer_size = 1 << 16;
			using SocketFilter = QVPN_SocketFilter;

		private:
			SOCKET socket_;

			QVPNSocketData socket_data_{};

			using TransportProtocol = QVPN::Core::TransportProtocol;
			using QVPNSocketSettings = QVPN::Core::QVPNSocketSettings;
			using ReceiveData = QVPN::Core::ReceiveData;
			using SafeReceiveSignal = QVPN::Core::SafeReceiveSignal;

			template <class AppLevelProtoTemplate>
			using SafeReceiveData = QVPN::Core::SafeReceiveData<AppLevelProtoTemplate>;

		public:

			QVPN_RawSocket();

			QVPN_RawSocket(int sock_family, int sock_type, int sock_proto);
			QVPN_RawSocket(const QVPN_RawSocket& other) noexcept;
			QVPN_RawSocket& operator=(const QVPN_RawSocket& other) noexcept;
			QVPN_RawSocket(QVPN_RawSocket&& other) noexcept;
			QVPN_RawSocket& operator=(QVPN_RawSocket&& other) noexcept;

			QVPN_RawSocket(SOCKET socket, QVPN::Core::IPv4Address remote_addr, UShort remote_port, QVPN::Core::IPv4Address local_addr, UShort local_port, TransportProtocol transport_proto);
			QVPN_RawSocket(SOCKET socket, QVPN::Core::IPv6Address remote_addr, UShort remote_port, QVPN::Core::IPv6Address local_addr, UShort local_port, TransportProtocol transport_proto);
			QVPN_RawSocket(SOCKET socket, QVPN::Core::NetAddr remote_addr, UShort remote_port, QVPN::Core::NetAddr local_addr, UShort local_port, TransportProtocol transport_proto);

			template<class ... Args>
			void create_socket_by_args(Args&& ... args)
			{
				socket_ = socket(std::forward<Args>(args)...);
			}

			bool is_valid() const;

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus connect(const Addr& addr, const UShort port)
			{
				QVPN::Core::NetStatus status{};
				QVPN::Core::NetData data{};
				status.success = false;

				data = QVPN::NetTools::details::qvpn_connect_(socket_, addr, port);
				status.status = data.status;
				status.success = data.success;

				if (status.success) {
					socket_data_.net_proto = data.addr.get_addr_family();
					socket_data_.remote_port = port;
					socket_data_.remote_addr = addr;
					socket_data_.local_port = data.port;
					socket_data_.local_addr = data.addr;
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
					socket_ = socket(meta.get_socket_family(socket_data_.local_addr.get_addr_family()), meta.get_raw_socket_type(socket_data_.transport_proto), meta.get_raw_socket_proto(socket_data_.transport_proto));
				}
				return connect<Addr>(addr, port);
			}

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus bind(const Addr& addr, const UShort port)
			{
				QVPN::Core::NetStatus status{};
				QVPN::Core::NetData data{};

				data = QVPN::NetTools::details::qvpn_bind_(socket_, addr, port);

				status.status = data.status;
				status.success = data.success;

				if (status.success) {
					socket_data_.net_proto = data.addr.get_addr_family();
					socket_data_.remote_port = port;
					socket_data_.remote_addr = addr;
					socket_data_.local_port = data.port;
					socket_data_.local_addr = data.addr;
				}

				return status;
			}

			template <QVPN::Core::is_addr Addr>
			QVPN_Socket accept()
			{
				return QVPN::NetTools::details::SocketAccept<QVPN::Core::NetProtocol::NET_UNDEFINED, Addr, QVPN_RawSocket>{}(socket_, socket_data_.local_addr.get_addr_family(), socket_data_.transport_proto);
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

				int timeout = settings.receive_timeout_ms();
				optlen = sizeof(timeout);
				setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), optlen);
			}

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus send_to(const Addr& addr, const UShort port, const UByte* begin, const UByte* end)
			{
				return NetTools::details::SocketSendTo<QVPN::Core::NetProtocol::NET_UNDEFINED, Addr, QVPN_RawSocket>{}(socket_, addr.get_addr_family(), addr, port, begin, end);
			}

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::ReceiveData recv_from(const Addr& addr, const UShort port)
			{
				return NetTools::details::SocketRecvFrom<QVPN::Core::NetProtocol::NET_UNDEFINED, Addr, QVPN_RawSocket>{}(socket_, addr.get_addr_family(), addr, port);
			}

			// Return full app level data
			template <QVPN::Core::is_proto_template NetLevelProtoTemplate, QVPN::Core::is_proto_template TransportLevelProtoTemplate, QVPN::Core::is_proto_template AppLevelProtoTemplate>
			SafeReceiveData<AppLevelProtoTemplate> safe_recv(int flags = 0)
			{
				int num_tries = 20;
				SafeReceiveData<AppLevelProtoTemplate> sf_data{};
				SafeReceiveSignal signal = SafeReceiveSignal::SFR_NO_DATA;
				while (signal != SafeReceiveSignal::SFR_FULL_DATA || signal == SafeReceiveSignal::SFR_ERROR || num_tries <= 0)
				{
					auto data = receive(flags);
					sf_data.set_status(data.status);
					if (!data.status.success)
					{
						num_tries--;
						continue;
					}
					signal = sf_data.add_objects_and_validate(signal, data.data.data(), data.data.data() + data.size);
				}

				return sf_data;
			}

			void filter(QVPN_SocketFilter& filter);

		};

	}

}
