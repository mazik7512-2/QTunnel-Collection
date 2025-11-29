#pragma once
#include <qvpn_lib.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>


#pragma comment(lib, "ws2_32.lib")

namespace QVPN {

	namespace NetTools {

		using UByte = QVPN::Core::BaseTypes::UByte;
		using UShort = QVPN::Core::BaseTypes::UShort;
		
		template <int addr_type, QVPN::Core::is_addr Addr>
		requires (addr_type == AF_INET)
		QVPN::Core::NetStatus connect_(SOCKET& socket, const QVPN::Core::UnifiedNetAddr<Addr>& addr, const UShort port)
		{
			sockaddr_in serverAddr;
			serverAddr.sin_family = QVPN::Core::UnifiedNetAddr<Addr>::get_addr_family();
			serverAddr.sin_port = htons(port);
			serverAddr.sin_addr = addr.to_uint();
			return connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
		}

		template <int addr_type, QVPN::Core::is_addr Addr>
		requires (addr_type == AF_INET6)
		QVPN::Core::NetStatus connect_(SOCKET& socket, const QVPN::Core::UnifiedNetAddr<Addr>& addr, const UShort port)
		{
			sockaddr_in6 serverAddr;
			serverAddr.sin6_family = QVPN::Core::UnifiedNetAddr<Addr>::get_addr_family();
			serverAddr.sin6_port = htons(port);
			serverAddr.sin6_addr = addr.to_uint();
			return connect(socket, (sockaddr*)&serverAddr, sizeof(serverAddr));
		}

		class WinSocket
		{
		public:
			static constexpr int buffer_size = 4096;

		private:
			SOCKET socket_;
			LPWSADATA wsa_data_;


		public:

			template <class ... Args>
			WinSocket(Args&& ... args)
			{
				socket_ = socket(std::forward<Args>(args)...);
			}

			template <QVPN::Core::is_addr Addr>
			QVPN::Core::NetStatus connect(const QVPN::Core::UnifiedNetAddr<Addr>& addr, const UShort port) const
			{
				QVPN::Core::NetStatus status{};
				status.success = false;
				auto res = WSAStartup(MAKEWORD(2, 2), reinterpret_cast<LPWSADATA&>(&wsa_data_));
				if (res != 0) {
					status.status = res;
					return status;
				}

				res = QVPN::NetTools::connect_<QVPN::Core::UnifiedNetAddr<Addr>::get_addr_family(), QVPN::Core::UnifiedNetAddr<Addr>>(socket_, addr, port);
				if (res == SOCKET_ERROR) {
					status.status = res;
					return status;
				}
				status.success = true;
				status.status = 0;
				return status;
			}

			QVPN::Core::NetStatus send(const UByte* begin, const UByte* end, int flags);

			std::array<UByte, WinSocket::buffer_size> receive(int flags);

			QVPN::Core::NetStatus disconnect() const;



		};


		class WinNetTools
		{


		public:

			static QVPN::NetTools::WinSocket create_socket(int socket_family, int socket_type, int proto);
		};


	}

}
