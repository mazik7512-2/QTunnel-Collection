#include <qvpn_net_tools.hpp>


using QVPNNetTools = QVPN::NetTools::QVPNNetTools;
using UByte = QVPN::Core::BaseTypes::UByte;
using UShort = QVPN::Core::BaseTypes::UShort;


QVPN::NetTools::QVPN_Socket QVPN::NetTools::QVPNNetTools::create_socket(int socket_family, int socket_type, int proto)
{
	QVPN::NetTools::QVPN_Socket socket(socket_family, socket_type, proto);
	return socket;
}


QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::send(const UByte* begin, const UByte* end, int flags)
{
	QVPN::Core::NetStatus status{};
	status.success = true;
	auto res = ::send(socket_, reinterpret_cast<const char*>(begin), std::distance(begin, end), flags);
	if (res == SOCKET_ERROR)
		status.success = true;
	status.status = res;
	return status;
}

std::array<UByte, QVPN::NetTools::QVPN_Socket::buffer_size> QVPN::NetTools::QVPN_Socket::receive(int flags)
{
	std::array<UByte, QVPN_Socket::buffer_size> buff{};
	recv(socket_, reinterpret_cast<char *>(buff.data()), QVPN_Socket::buffer_size, flags);
	return buff;
}

QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::disconnect() const
{
	closesocket(socket_);
	WSACleanup();
	return QVPN::Core::NetStatus{ true, 0 };
}
