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
		
		// on odr usage
		inline QVPN::Core::NetStatus qvpn_connect_(SOCKET& socket, const QVPN::Core::IPv4Address& addr, const UShort port)
		{
			sockaddr_in serverAddr{};          
			serverAddr.sin_family = AF_INET;
			serverAddr.sin_port = htons(port);
			serverAddr.sin_addr.S_un.S_addr = addr.to_uint();//std::visit([](const auto& address) { return address.to_uint(); }, addr);
			int res = connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
			bool s = (res == 0) ? true : false;
			return QVPN::Core::NetStatus{ s , res };
		}

		// no odr usage
		inline QVPN::Core::NetStatus qvpn_connect_(SOCKET& socket, const QVPN::Core::Ipv6Address& addr, const UShort port)
		{
			struct sockaddr_in6 serverAddr{};
			serverAddr.sin6_family = AF_INET6;
			serverAddr.sin6_port = htons(port);
			//serverAddr.sin6_addr.u.Byte = addr.to_bytes();//std::visit([](const auto& address) { return address.to_bytes(); }, addr);
			auto bytes = addr.to_bytes();
			std::memcpy(&serverAddr.sin6_addr.u.Byte, bytes.data(), bytes.size());
			int res = connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
			bool s = (res == 0) ? true : false;
			return QVPN::Core::NetStatus{ s , res };
		}
		

		class QVPN_Socket
		{
		public:
			static constexpr int buffer_size = 4096;

		private:
			SOCKET socket_;
			WSADATA wsa_data_;

		public:

			template <class ... Args>
			QVPN_Socket(Args&& ... args)
			{
				socket_ = socket(std::forward<Args>(args)...);
			}
			
			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus connect(const Addr& addr, const UShort port)
			{
				QVPN::Core::NetStatus status{};
				status.success = false;
				auto res = WSAStartup(MAKEWORD(2, 2), &wsa_data_);
				if (res != 0) {
					status.status = res;
					return status;
				}
				status = QVPN::NetTools::qvpn_connect_(socket_, addr, port);
				return status;
			}
			
			QVPN::Core::NetStatus send(const UByte* begin, const UByte* end, int flags = 0);

			std::array<UByte, QVPN_Socket::buffer_size> receive(int flags = 0);

			QVPN::Core::NetStatus disconnect() const;



		};


		class QVPNNetTools
		{
		public:

			static QVPN::NetTools::QVPN_Socket create_socket(int socket_family = AF_INET, int socket_type = SOCK_STREAM, int proto = IPPROTO_TCP);
		};


	}

}
