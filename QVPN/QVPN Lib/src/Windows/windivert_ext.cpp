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
    if (t.filter_.empty())
        return *this;
    else if (filter_.empty())
    {
        filter_ = t.filter_;
        return *this;
    }

    std::stringstream f;
    f << filter_ << " and " << t.filter_;
    filter_ = f.str(); 
    return *this;
}

WinDivertTrafficFilterType& QVPN::WinDivertExt::WinDivertTrafficFilterType::operator||(const WinDivertTrafficFilterType& t)
{
    if (filter_.empty())
        return *this;
    else if (t.filter_.empty())
    {
        filter_ = t.filter_;
        return *this;
    }

    std::stringstream f;
    f << filter_ << " or " << t.filter_;
    return *this;
}

WinDivertTrafficFilterType& QVPN::WinDivertExt::WinDivertTrafficFilterType::operator!()
{
    auto eq_pos = filter_.find('=');
    if (eq_pos != std::string::npos)
        filter_.insert(eq_pos, "!");
    else
        filter_.insert(filter_.cbegin(), '!');
    return *this;
}
