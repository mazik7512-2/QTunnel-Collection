#include <qvpn_net_tools.hpp>


using QVPNNetTools = QVPN::NetTools::QVPNNetTools;
using UByte = QVPN::Core::BaseTypes::UByte;
using UShort = QVPN::Core::BaseTypes::UShort;


QVPN::NetTools::QVPN_Socket QVPN::NetTools::QVPNNetTools::create_socket(int socket_family, int socket_type, int proto)
{
	QVPN::NetTools::QVPN_Socket socket(socket_family, socket_type, proto);
	return socket;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket()
	: s_mod_(UNDEFINED)
{
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::IPv4Address remote_addr, UShort remote_port, QVPN::Core::IPv4Address local_addr, UShort local_port, SocketMod s_mod)
{
	socket_ = socket;
	remote_addr_ = remote_addr;
	remote_port_ = remote_port;
	local_addr_ = local_addr;
	local_port_ = local_port;
	s_mod_ = s_mod;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::IPv6Address remote_addr, UShort remote_port, QVPN::Core::IPv6Address local_addr, UShort local_port, SocketMod s_mod)
{
	socket_ = socket;
	remote_addr_ = remote_addr;
	remote_port_ = remote_port;
	local_addr_ = local_addr;
	local_port_ = local_port;
	s_mod_ = s_mod;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::NetAddr remote_addr, UShort remote_port, QVPN::Core::NetAddr local_addr, UShort local_port, SocketMod s_mod)
{
	socket_ = socket;
	remote_addr_ = remote_addr;
	remote_port_ = remote_port;
	local_addr_ = local_addr;
	local_port_ = local_port;
	s_mod_ = s_mod;
}


QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::listen(int con_limit)
{
	auto res = ::listen(socket_, con_limit);
	bool s = (res == 0) ? true : false;
	return QVPN::Core::NetStatus{ s , res };
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

QVPN::Core::NetStatus QVPN::NetTools::QVPN_Socket::shutdown()
{
	auto res = ::shutdown(socket_, SD_SEND);
	WSACleanup();
	bool s = (res == 0) ? true : false;
	return QVPN::Core::NetStatus{ s, res };
}
