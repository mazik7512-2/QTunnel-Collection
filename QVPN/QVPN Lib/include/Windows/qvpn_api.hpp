#pragma once

#include <qvpn_lib.hpp>
#include <windivert_ext.hpp>
#include <wintun_ext.hpp>
#include <qvpn_net_tools.hpp>
#include <qvpn_driver.hpp>

namespace QVPN
{

	namespace details
	{
		using QVPNSocket = QVPN::NetTools::QVPN_Socket;
		using QVPNNetTools = QVPN::NetTools::QVPNNetTools;
		using QVPNServerDriver = QVPN::Core::QVPNServerDriver<QVPN::Core::BaseTypes::UByte*, QVPN::Core::NetAddr, QVPNSocket, QVPNNetTools>;
	}

	using QVPNClientSettings = QVPN::Core::QVPNClientSettings;
	using QVPNClient = QVPN::Core::VPNClient<QVPN::WinTunExt::WinTunDriver, QVPN::WinDivertExt::WinDivertClientNetDriver>;
	using QVPNLayersStrategy = QVPN::Core::DefaultLayersStrategy<QVPN::Core::BaseTypes::UByte*, QVPN::Core::NetAddr>;

	using QVPNServerSettings = QVPN::Core::QVPNServerSettings;


	using QVPNServer = QVPN::Core::VPNServer_<QVPN::Core::BaseTypes::UByte*, details::QVPNServerDriver>;
	
	
}