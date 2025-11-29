#include <qvpn_net_tools.hpp>


using WinNetTools = QVPN::NetTools::WinNetTools;
using UByte = QVPN::Core::BaseTypes::UByte;
using UShort = QVPN::Core::BaseTypes::UShort;


QVPN::NetTools::WinSocket QVPN::NetTools::WinNetTools::create_socket(int socket_family = AF_INET, int socket_type = SOCK_STREAM, int proto = IPPROTO_TCP)
{
	QVPN::NetTools::WinSocket socket(socket_family, socket_type, proto);
	return socket;
}


QVPN::Core::NetStatus QVPN::NetTools::WinSocket::send(const UByte* begin, const UByte* end, int flags)
{
	QVPN::Core::NetStatus status{};
	status.success = true;
	auto res = ::send(socket_, reinterpret_cast<const char*>(begin), std::distance(begin, end), flags);
	if (res == SOCKET_ERROR)
		status.success = true;
	status.status = res;
	return status;
}

std::array<UByte, QVPN::NetTools::WinSocket::buffer_size> QVPN::NetTools::WinSocket::receive(int flags)
{
	std::array<UByte, WinSocket::buffer_size> buff{};
	recv(socket_, reinterpret_cast<char *>(buff.data()), WinSocket::buffer_size, flags);
	return buff;
}

QVPN::Core::NetStatus QVPN::NetTools::WinSocket::disconnect() const
{
	closesocket(socket_);
	WSACleanup();
	return QVPN::Core::NetStatus{ true, 0 };
}
