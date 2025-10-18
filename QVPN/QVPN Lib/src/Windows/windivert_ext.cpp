#include <windivert_ext.hpp>
#include <sstream>

using WinDivertTrafficFilterType = QVPN::WinDivertExt::WinDivertTrafficFilterType;

QVPN::WinDivertExt::WinDivertTrafficFilterType::WinDivertTrafficFilterType()
{
    
}

QVPN::WinDivertExt::WinDivertTrafficFilterType::WinDivertTrafficFilterType(Convertable_from filter)
{
    filter_ = filter;
}


QVPN::WinDivertExt::WinDivertTrafficFilterType::WinDivertTrafficFilterType(const WinDivertTrafficFilterType& filter)
{
    filter_ = filter.filter_;
}

QVPN::WinDivertExt::WinDivertTrafficFilterType::WinDivertTrafficFilterType(WinDivertTrafficFilterType&& filter) noexcept
{
    std::swap(filter_, filter.filter_);
}

WinDivertTrafficFilterType& QVPN::WinDivertExt::WinDivertTrafficFilterType::operator=(const WinDivertTrafficFilterType& filter)
{
    filter_ = filter.filter_;
    return *this;
}


WinDivertTrafficFilterType& QVPN::WinDivertExt::WinDivertTrafficFilterType::operator=(WinDivertTrafficFilterType&& filter) noexcept
{
    std::swap(filter_, filter.filter_);
    return *this;
}



QVPN::WinDivertExt::WinDivertTrafficFilterType::operator Convertable_to() const
{
    return filter_;
}

QVPN::WinDivertExt::WinDivertTrafficFilterType& QVPN::WinDivertExt::WinDivertTrafficFilterType::operator&&(const WinDivertTrafficFilterType& t)
{
    std::stringstream f;
    if (!filter_.empty())
        f << filter_ << " and " << t.filter_;
    else
        f << " " << t.filter_;
    filter_ = f.str(); 
    return *this;
}
