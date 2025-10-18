#pragma once

#include <lib.hpp>
#include <windivert_ext.hpp>
#include <wintun_ext.hpp>

namespace QVPN
{
	using VPNClientDriver = QVPN::Core::VPNClientDriver_<QVPN::WinTunExt::WinTunDriver, QVPN::WinDivertExt::WinDivertClientNetDriver>;
	
}