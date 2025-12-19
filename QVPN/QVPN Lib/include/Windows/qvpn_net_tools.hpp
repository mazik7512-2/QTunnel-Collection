#pragma once

#include <qvpn_lib.hpp>

#include <winsock2.h>     
#include <ws2ipdef.h>
#include <variant>

#pragma comment(lib, "ws2_32.lib")

namespace QVPN {

	namespace NetTools {

		using UByte = QVPN::Core::BaseTypes::UByte;
		using UShort = QVPN::Core::BaseTypes::UShort;
		using QVPNSocketData = QVPN::Core::QVPNSocketData;

		namespace details
		{
			// inline - no odr usage
			inline QVPN::Core::NetData qvpn_connect_(SOCKET& socket, const QVPN::Core::IPv4Address& addr, const UShort port)
			{
				sockaddr_in sock_addr{};
				int addr_len = sizeof(sock_addr);;

				struct sockaddr_in serverAddr {};
				serverAddr.sin_family = AF_INET;
				serverAddr.sin_port = htons(port);
				serverAddr.sin_addr.S_un.S_addr = addr.to_uint();//std::visit([](const auto& address) { return address.to_uint(); }, addr);

				int res = connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
				getsockname(socket, (sockaddr*)&sock_addr, &addr_len);

				QVPN::Core::NetAddr net_addr((UByte*)&sock_addr.sin_addr.S_un.S_un_b, (UByte*)&sock_addr.sin_addr.S_un.S_un_b + addr_len);

				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetData{ s , res, net_addr, sock_addr.sin_port };
			}

			inline QVPN::Core::NetData qvpn_connect_(SOCKET& socket, const QVPN::Core::IPv6Address& addr, const UShort port)
			{
				sockaddr_in6 sock_addr{};
				int addr_len = sizeof(sockaddr);

				struct sockaddr_in6 serverAddr {};
				serverAddr.sin6_family = AF_INET6;
				serverAddr.sin6_port = htons(port);
				//serverAddr.sin6_addr.u.Byte = addr.to_bytes();//std::visit([](const auto& address) { return address.to_bytes(); }, addr);
				auto bytes = addr.to_bytes();
				std::memcpy(&serverAddr.sin6_addr.u.Byte, bytes.data(), bytes.size());
				int res = connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));

				getsockname(socket, (sockaddr*)&sock_addr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)&sock_addr.sin6_addr.u.Byte, (UByte*)&sock_addr.sin6_addr.u.Byte + addr_len);

				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetData{ s , res, net_addr, sock_addr.sin6_port };
			}


			inline QVPN::Core::NetData qvpn_connect_(SOCKET& socket, const QVPN::Core::NetAddr& addr, const UShort port)
			{
				auto addr_family = addr.get_addr_family();
				switch (addr_family)
				{
				case QVPN::Core::NetProtocols::IPv4:
					return qvpn_connect_(socket, addr.to_ipv4(), port);
				case QVPN::Core::NetProtocols::IPv6:
					return qvpn_connect_(socket, addr.to_ipv6(), port);
				default:
					return QVPN::Core::NetData{ false, 0 };
				}
				
			}


			inline QVPN::Core::NetData qvpn_bind_(SOCKET& socket, const QVPN::Core::IPv4Address& addr, const UShort port)
			{
				sockaddr_in sock_addr{};
				int addr_len = sizeof(sock_addr);;

				struct sockaddr_in serverAddr {};
				serverAddr.sin_family = AF_INET;
				serverAddr.sin_port = htons(port);
				serverAddr.sin_addr.S_un.S_addr = addr.to_uint();//std::visit([](const auto& address) { return address.to_uint(); }, addr);
				int res = bind(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));

				getsockname(socket, (sockaddr*)&sock_addr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)&sock_addr.sin_addr.S_un.S_un_b, (UByte*)&sock_addr.sin_addr.S_un.S_un_b + addr_len);

				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetData{ s , res, net_addr, sock_addr.sin_port };
			}

			inline QVPN::Core::NetData qvpn_bind_(SOCKET& socket, const QVPN::Core::IPv6Address& addr, const UShort port)
			{

				sockaddr_in6 sock_addr{};
				int addr_len = sizeof(sock_addr);;

				struct sockaddr_in6 serverAddr {};
				serverAddr.sin6_family = AF_INET6;
				serverAddr.sin6_port = htons(port);
				//serverAddr.sin6_addr.u.Byte = addr.to_bytes();//std::visit([](const auto& address) { return address.to_bytes(); }, addr);
				auto bytes = addr.to_bytes();
				std::memcpy(&serverAddr.sin6_addr.u.Byte, bytes.data(), bytes.size());
				int res = bind(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));

				getsockname(socket, (sockaddr*)&sock_addr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)& sock_addr.sin6_addr.u.Byte, (UByte*)&sock_addr.sin6_addr.u.Byte + addr_len);

				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetData{ s , res, net_addr, sock_addr.sin6_port };
			}

			inline QVPN::Core::NetData qvpn_bind_(SOCKET& socket, const QVPN::Core::NetAddr& addr, const UShort port)
			{
				auto addr_family = addr.get_addr_family();
				switch (addr_family)
				{
				case QVPN::Core::NetProtocols::IPv4:
					return qvpn_bind_(socket, addr.to_ipv4(), port);
				case QVPN::Core::NetProtocols::IPv6:
					return qvpn_bind_(socket, addr.to_ipv6(), port);
				default:
					return QVPN::Core::NetData{ false, 0 };
				}
			}

		}

		enum SocketMod
		{
			SERVER_MOD = 0,
			CLIENT_MOD = 1,
			UNDEFINED = 2
		};

		class QVPN_Socket
		{
		public:
			static constexpr int buffer_size = 1 << 16;

		private:
			SOCKET socket_;
			WSADATA wsa_data_{};

			QVPNSocketData socket_data_{};

			SocketMod s_mod_ = UNDEFINED;

		public:

			QVPN_Socket();

			template <class ... Args>
			QVPN_Socket(Args&& ... args)
			{
				socket_ = socket(std::forward<Args>(args)...);
				socket_data_.remote_port = 0;
				socket_data_.local_port = 0;
				s_mod_ = UNDEFINED;
			}
			
			QVPN_Socket(SOCKET socket, QVPN::Core::IPv4Address remote_addr, UShort remote_port, QVPN::Core::IPv4Address local_addr, UShort local_port, SocketMod s_mod);
			QVPN_Socket(SOCKET socket, QVPN::Core::IPv6Address remote_addr, UShort remote_port, QVPN::Core::IPv6Address local_addr, UShort local_port, SocketMod s_mod);
			QVPN_Socket(SOCKET socket, QVPN::Core::NetAddr remote_addr, UShort remote_port, QVPN::Core::NetAddr local_addr, UShort local_port, SocketMod s_mod);

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
				auto res = WSAStartup(MAKEWORD(2, 2), &wsa_data_);
				if (res != 0) {
					status.status = res;
					return status;
				}
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
			QVPN::Core::NetStatus bind(const Addr& addr, const UShort port)
			{
				if (s_mod_ == CLIENT_MOD)
					return QVPN::Core::NetStatus{ false, 0 };
				QVPN::Core::NetStatus status{};
				QVPN::Core::NetData data{};
				auto res = WSAStartup(MAKEWORD(2, 2), &wsa_data_);
				if (res != 0) {
					status.success = false;
					status.status = res;
					return status;
				}
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
				return qvpn_accept_<Addr>(socket_);
			}

			QVPN::Core::NetStatus listen(int con_limit = SOMAXCONN);

			QVPN::Core::NetStatus send(const UByte* begin, const UByte* end, int flags = 0);

			std::pair<QVPN::Core::NetStatus, std::array<UByte, QVPN_Socket::buffer_size>> receive(int flags = 0);

			QVPN::Core::NetStatus disconnect() const;

			QVPN::Core::NetStatus shutdown();

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

		};


		namespace details
		{

			template <QVPN::Core::is_addr Addr>
			inline QVPN_Socket qvpn_accept_(SOCKET& socket)
			{
				return QVPN_Socket{};
			}

			template <>
			inline QVPN_Socket qvpn_accept_<QVPN::Core::IPv4Address>(SOCKET& socket)
			{
				sockaddr_in sock_addr{};
				int addr_len = sizeof(sock_addr);;

				struct sockaddr_in clientAddr {};
				int clientAddrLen = sizeof(clientAddr);
				auto sock = ::accept(socket, (sockaddr*)&clientAddr, &clientAddrLen);

				getsockname(sock, (sockaddr*)&sock_addr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)& sock_addr.sin_addr.S_un.S_un_b, (UByte*)&sock_addr.sin_addr.S_un.S_un_b + addr_len);

				QVPN::Core::NetAddr addr((UByte*)&clientAddr.sin_addr.S_un.S_un_b, (UByte*)&clientAddr.sin_addr.S_un.S_un_b + addr_len);
				UShort port = clientAddr.sin_port;
				return QVPN_Socket(sock, addr, port, net_addr, sock_addr.sin_port, SERVER_MOD);
			}

			template <>
			inline QVPN_Socket qvpn_accept_<QVPN::Core::IPv6Address>(SOCKET& socket)
			{
				sockaddr_in6 sock_addr{};
				int addr_len = sizeof(sock_addr);;

				struct sockaddr_in6 clientAddr {};
				int clientAddrLen = sizeof(clientAddr);
				auto sock = ::accept(socket, (sockaddr*)&clientAddr, &clientAddrLen);

				getsockname(sock, (sockaddr*)&sock_addr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)&sock_addr.sin6_addr.u.Byte, (UByte*)&sock_addr.sin6_addr.u.Byte + addr_len);

				QVPN::Core::NetAddr addr((UByte*)&clientAddr.sin6_addr.u.Byte, (UByte*)&clientAddr.sin6_addr.u.Byte + addr_len);
				UShort port = clientAddr.sin6_port;
				return QVPN_Socket(sock, addr, port, net_addr, sock_addr.sin6_port, SERVER_MOD);
			}

			// Должно уместить все (и ipv4, и ipv6)
			template <>
			inline QVPN_Socket qvpn_accept_<QVPN::Core::NetAddr>(SOCKET& socket)
			{
				sockaddr_in6 sock_addr{};
				int addr_len = sizeof(sock_addr);;

				struct sockaddr_in6 clientAddr {};
				int clientAddrLen = sizeof(clientAddr);
				auto sock = ::accept(socket, (sockaddr*)&clientAddr, &clientAddrLen);

				getsockname(sock, (sockaddr*)&sock_addr, &addr_len);
				QVPN::Core::NetAddr net_addr((UByte*)&sock_addr.sin6_addr.u.Byte, (UByte*)&sock_addr.sin6_addr.u.Byte + addr_len);

				QVPN::Core::NetAddr addr((UByte*)&clientAddr.sin6_addr.u.Byte, (UByte*)&clientAddr.sin6_addr.u.Byte + addr_len);
				UShort port = clientAddr.sin6_port;
				return QVPN_Socket(sock, addr, port, net_addr, sock_addr.sin6_port, SERVER_MOD);
			}

		}

		class QVPNNetTools
		{
		public:

			static QVPN::NetTools::QVPN_Socket create_socket(int socket_family = AF_INET, int socket_type = SOCK_STREAM, int proto = IPPROTO_TCP);
		};

	}

}
