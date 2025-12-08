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

		namespace details
		{
			// no odr usage
			inline QVPN::Core::NetStatus qvpn_connect_(SOCKET& socket, const QVPN::Core::IPv4Address& addr, const UShort port)
			{
				struct sockaddr_in serverAddr {};
				serverAddr.sin_family = AF_INET;
				serverAddr.sin_port = htons(port);
				serverAddr.sin_addr.S_un.S_addr = addr.to_uint();//std::visit([](const auto& address) { return address.to_uint(); }, addr);
				int res = connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetStatus{ s , res };
			}

			// no odr usage
			inline QVPN::Core::NetStatus qvpn_connect_(SOCKET& socket, const QVPN::Core::IPv6Address& addr, const UShort port)
			{
				struct sockaddr_in6 serverAddr {};
				serverAddr.sin6_family = AF_INET6;
				serverAddr.sin6_port = htons(port);
				//serverAddr.sin6_addr.u.Byte = addr.to_bytes();//std::visit([](const auto& address) { return address.to_bytes(); }, addr);
				auto bytes = addr.to_bytes();
				std::memcpy(&serverAddr.sin6_addr.u.Byte, bytes.data(), bytes.size());
				int res = connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetStatus{ s , res };
			}


			inline QVPN::Core::NetStatus qvpn_bind_(SOCKET& socket, const QVPN::Core::IPv4Address& addr, const UShort port)
			{
				struct sockaddr_in serverAddr {};
				serverAddr.sin_family = AF_INET;
				serverAddr.sin_port = htons(port);
				serverAddr.sin_addr.S_un.S_addr = addr.to_uint();//std::visit([](const auto& address) { return address.to_uint(); }, addr);
				int res = bind(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetStatus{ s , res };
			}

			inline QVPN::Core::NetStatus qvpn_bind_(SOCKET& socket, const QVPN::Core::IPv6Address& addr, const UShort port)
			{
				struct sockaddr_in6 serverAddr {};
				serverAddr.sin6_family = AF_INET6;
				serverAddr.sin6_port = htons(port);
				//serverAddr.sin6_addr.u.Byte = addr.to_bytes();//std::visit([](const auto& address) { return address.to_bytes(); }, addr);
				auto bytes = addr.to_bytes();
				std::memcpy(&serverAddr.sin6_addr.u.Byte, bytes.data(), bytes.size());
				int res = bind(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
				bool s = (res == 0) ? true : false;
				return QVPN::Core::NetStatus{ s , res };
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
			static constexpr int buffer_size = 4096;

		private:
			SOCKET socket_;
			WSADATA wsa_data_{};

			std::variant<QVPN::Core::IPv4Address, QVPN::Core::IPv6Address> addr_;
			UShort port_;

			SocketMod s_mod_ = UNDEFINED;

		public:

			template <class ... Args>
			QVPN_Socket(Args&& ... args)
			{
				socket_ = socket(std::forward<Args>(args)...);
				port_ = 0;
				s_mod_ = UNDEFINED;
			}
			
			QVPN_Socket(SOCKET socket, QVPN::Core::IPv4Address addr, UShort port, SocketMod s_mod);
			QVPN_Socket(SOCKET socket, QVPN::Core::IPv6Address addr, UShort port, SocketMod s_mod);

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus connect(const Addr& addr, const UShort port)
			{
				if (s_mod_ == SERVER_MOD)
					return QVPN::Core::NetStatus{ false, 0 };
				QVPN::Core::NetStatus status{};
				status.success = false;
				auto res = WSAStartup(MAKEWORD(2, 2), &wsa_data_);
				if (res != 0) {
					status.status = res;
					return status;
				}
				status = QVPN::NetTools::details::qvpn_connect_(socket_, addr, port);

				if (status.success) {
					port_ = port;
					addr_ = addr;
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
				auto res = WSAStartup(MAKEWORD(2, 2), &wsa_data_);
				if (res != 0) {
					status.success = false;
					status.status = res;
					return status;
				}
				status = QVPN::NetTools::details::qvpn_bind_(socket_, addr, port);

				if (status.success) {
					port_ = port;
					addr_ = addr;
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

			std::array<UByte, QVPN_Socket::buffer_size> receive(int flags = 0);

			QVPN::Core::NetStatus disconnect() const;

			QVPN::Core::NetStatus shutdown();


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
				struct sockaddr_in clientAddr {};
				int clientAddrLen = sizeof(clientAddr);
				auto sock = ::accept(socket, (sockaddr*)&clientAddr, &clientAddrLen);

				QVPN::Core::IPv4Address addr(clientAddr.sin_addr.S_un.S_addr);
				UShort port = clientAddr.sin_port;
				return QVPN_Socket(sock, addr, port, CLIENT_MOD);
			}

			template <>
			inline QVPN_Socket qvpn_accept_<QVPN::Core::IPv6Address>(SOCKET& socket)
			{
				struct sockaddr_in6 clientAddr {};
				int clientAddrLen = sizeof(clientAddr);
				auto sock = ::accept(socket, (sockaddr*)&clientAddr, &clientAddrLen);

				QVPN::Core::IPv6Address addr(clientAddr.sin6_addr.u.Byte);
				UShort port = clientAddr.sin6_port;
				return QVPN_Socket(sock, addr, port, CLIENT_MOD);
			}
		}
		class QVPNNetTools
		{
		public:

			static QVPN::NetTools::QVPN_Socket create_socket(int socket_family = AF_INET, int socket_type = SOCK_STREAM, int proto = IPPROTO_TCP);
		};


	}

}
