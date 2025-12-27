#include <qvpn_net_tools.hpp>


using QVPNNetTools = QVPN::NetTools::QVPNNetTools;
using UByte = QVPN::Core::BaseTypes::UByte;
using UShort = QVPN::Core::BaseTypes::UShort;


QVPN::NetTools::QVPN_Socket QVPN::NetTools::QVPNNetTools::create_socket(QVPN::Core::NetProtocols net_proto, QVPN::Core::TransportProtocols t_proto)
{
	QVPNMetaSocketData meta{};
	return QVPN::NetTools::QVPN_Socket(meta.get_socket_family(net_proto), meta.get_socket_type(t_proto), meta.get_socket_type(t_proto));
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket()
	: s_mod_(UNDEFINED), socket_(NULL)
{
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(const QVPN_Socket& other) noexcept
{
	socket_ = other.socket_;
	wsa_data_ = other.wsa_data_;
	socket_data_ = other.socket_data_;
	s_mod_ = other.s_mod_;
}

QVPN::NetTools::QVPN_Socket& QVPN::NetTools::QVPN_Socket::operator=(const QVPN_Socket& other) noexcept
{
	socket_ = other.socket_;
	wsa_data_ = other.wsa_data_;
	socket_data_ = other.socket_data_;
	s_mod_ = other.s_mod_;
	return *this;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(QVPN_Socket&& other) noexcept
{
	socket_ = std::move(other.socket_);
	wsa_data_ = std::move(other.wsa_data_);
	socket_data_ = std::move(other.socket_data_);
	s_mod_ = std::move(other.s_mod_);
}

QVPN::NetTools::QVPN_Socket& QVPN::NetTools::QVPN_Socket::operator=(QVPN_Socket&& other) noexcept
{
	socket_ = std::move(other.socket_);
	wsa_data_ = std::move(other.wsa_data_);
	socket_data_ = std::move(other.socket_data_);
	s_mod_ = std::move(other.s_mod_);
	return *this;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::IPv4Address remote_addr, UShort remote_port, QVPN::Core::IPv4Address local_addr, UShort local_port, SocketMod s_mod)
{
	socket_ = socket;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	s_mod_ = s_mod;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::IPv6Address remote_addr, UShort remote_port, QVPN::Core::IPv6Address local_addr, UShort local_port, SocketMod s_mod)
{
	socket_ = socket;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
	s_mod_ = s_mod;
}

QVPN::NetTools::QVPN_Socket::QVPN_Socket(SOCKET socket, QVPN::Core::NetAddr remote_addr, UShort remote_port, QVPN::Core::NetAddr local_addr, UShort local_port, SocketMod s_mod)
{
	socket_ = socket;
	socket_data_.remote_addr = remote_addr;
	socket_data_.remote_port = remote_port;
	socket_data_.local_addr = local_addr;
	socket_data_.local_port = local_port;
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

std::pair<QVPN::Core::NetStatus, std::array<UByte, QVPN::NetTools::QVPN_Socket::buffer_size>> QVPN::NetTools::QVPN_Socket::receive(int flags)
{
	QVPN::Core::NetStatus status{};
	std::array<UByte, QVPN_Socket::buffer_size> buff{};
	auto res = recv(socket_, reinterpret_cast<char *>(buff.data()), QVPN_Socket::buffer_size, flags);
	status.status = res;
	status.success = (res > 0) ? true : false;
	return std::pair<QVPN::Core::NetStatus, std::array<UByte, QVPN_Socket::buffer_size>>(status, std::move(buff));
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

QVPN::NetTools::QVPNMetaSocketData::SockParam QVPN::NetTools::QVPNMetaSocketData::get_socket_family(QVPN::Core::NetProtocols net_proto)
{
	return families_[net_proto];
}

QVPN::NetTools::QVPNMetaSocketData::SockParam QVPN::NetTools::QVPNMetaSocketData::get_socket_type(QVPN::Core::TransportProtocols t_proto)
{
	return types_[t_proto];
}

QVPN::NetTools::QVPNMetaSocketData::SockParam QVPN::NetTools::QVPNMetaSocketData::get_socket_proto(QVPN::Core::TransportProtocols t_proto)
{
	return protos_[t_proto];
}
