#pragma once

#include <qvpn_lib.hpp>
#include <windivert_ext.hpp>
#include <wintun_ext.hpp>
#include <qvpn_driver.hpp>

namespace QVPN
{
	using VPNSettings = QVPN::Core::QVPNSettings;
	using VPNClient = QVPN::Core::VPNClient_<QVPN::WinTunExt::WinTunDriver, QVPN::WinDivertExt::WinDivertClientNetDriver>;
	
}