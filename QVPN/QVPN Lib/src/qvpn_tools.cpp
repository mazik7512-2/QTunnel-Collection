#include <qvpn_tools.hpp>
#include <algorithm>

// Http tools

QVPN::Core::HttpTools::HttpRequestType QVPN::Core::HttpTools::get_request_type_by_string(std::string_view request_type)
{
	try {
		return request_types_.at(str_to_upper(request_type.begin(), request_type.end()));
	}
	catch (const std::out_of_range& e)
	{
		return HttpRequestType::UNKNOWN;
	}
}

std::string QVPN::Core::HttpTools::str_to_upper(std::string_view::iterator begin, std::string_view::iterator end)
{
	std::string res;
	std::transform(begin, end, std::back_inserter(res), [](char c) {return std::toupper(c); });
	return res;
}

bool QVPN::Core::HttpTools::case_free_compare(char a, char b)
{
	return std::tolower(static_cast<unsigned char>(a)) ==
		std::tolower(static_cast<unsigned char>(b));
}

int QVPN::Core::HttpTools::case_free_search(std::string_view source, std::string_view templ)
{
	auto it = std::search(source.begin(), source.end(),
		templ.begin(), templ.end(),
		case_free_compare);
	return std::distance(source.begin(), it);
}

QVPN::Core::HttpTools::HttpConnectionType QVPN::Core::HttpTools::get_http_connection_type_by_string(std::string_view connection_type)
{
	try {
		return con_types_.at(str_to_upper(connection_type.begin(), connection_type.end()));
	}
	catch (const std::out_of_range& e)
	{
		return HttpConnectionType::UNKNOWN;
	}
}

std::string_view QVPN::Core::HttpTools::get_http_header_line(std::string_view http_data, std::string_view header_name)
{
	constexpr std::string_view endline = "\r\n";
	auto start = HttpTools::case_free_search(http_data, header_name);
	auto line_end = http_data.find(endline, start);
	return std::string_view(http_data.substr(start + header_name.size(), line_end));
}

std::string_view QVPN::Core::HttpTools::get_http_header_block(std::string_view http_data, std::string_view header_name)
{
	constexpr std::string_view endblock = " ";
	auto start = HttpTools::case_free_search(http_data, header_name);
	auto line_end = http_data.find(endblock, start);
	return std::string_view(http_data.substr(start + header_name.size(), line_end));
}

QVPN::Core::HttpTools::HttpVersion QVPN::Core::HttpTools::get_http_version_by_string(std::string_view version)
{
	try {
		return versions_.at(version);
	}
	catch (const std::out_of_range& e)
	{
		return HttpVersion::UNKNOWN;
	}
}

QVPN::Core::HttpTools::HttpResponseStatus QVPN::Core::HttpTools::get_http_status_by_string(std::string_view status)
{
	try {
		return statuses_.at(status);
	}
	catch (const std::out_of_range& e)
	{
		return HttpResponseStatus::UNKNOWN;
	}
}

QVPN::Core::HttpTools::HttpContentType QVPN::Core::HttpTools::get_http_content_type_by_string(std::string_view content)
{
	try {
		return content_types_.at(content);
	}
	catch (const std::out_of_range& e)
	{
		return HttpContentType::UNKNOWN;
	}
}

QVPN::Core::HttpTools::QVPNCharset QVPN::Core::HttpTools::get_http_charset_by_string(std::string_view charset)
{
	try {
		return charsets_.at(charset);
	}
	catch (const std::out_of_range& e)
	{
		return QVPNCharset::UNKNOWN;
	}
}

std::pair<std::uniform_int_distribution<QVPN::Core::TLSTools::UInt>, std::mt19937> QVPN::Core::TLSTools::get_bytes_randomizer()
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<UInt> dist(0, 255);
	return std::pair<std::uniform_int_distribution<UInt>, std::mt19937>(dist, gen);
}

std::vector<QVPN::Core::BaseTypes::UByte> QVPN::Core::Tools::parse_net_addr(std::string_view addr)
{
	std::vector<QVPN::Core::BaseTypes::UByte> ip_;
	auto delim = "."; // ipv4
	size_t start = 0;
	size_t end = addr.find(delim, start);

	if (end == std::string_view::npos) 
		delim = "::"; // ipv6

	for (size_t i = 0; i < 16; i++)
	{
		end = addr.find(delim, start);
		auto elem = addr.substr(start, end - start);
		ip_.push_back(std::stoi(std::string(elem)));
		start = end + 1;
		if (end == std::string_view::npos)
			break;
	}
	return ip_;
}


void QVPN::Core::Tools::QVPNSpeedMeter::recv_meter_start()
{
	recv_first_fixation_ = Clock::now();
	recv_last_fixation_ = {};
}

void QVPN::Core::Tools::QVPNSpeedMeter::send_meter_start()
{
	send_first_fixation_ = Clock::now();
	send_last_fixation_ = {};
}

void QVPN::Core::Tools::QVPNSpeedMeter::add_receive_size(UInt bytes, Clock::time_point fix_time)
{
	recv_last_bytes_ = bytes;
	recv_total_bytes_ += bytes;

	recv_last_fixation_ = fix_time;
}

void QVPN::Core::Tools::QVPNSpeedMeter::add_send_size(UInt bytes, Clock::time_point fix_time)
{
	send_last_bytes_ = bytes;
	send_total_bytes_ += bytes;

	send_last_fixation_ = fix_time;
}

double QVPN::Core::Tools::QVPNSpeedMeter::get_last_recv_speed() const
{
	constexpr UInt delta_safe = 1;

	auto now = Clock::now();
	auto delta_time = std::chrono::duration_cast<std::chrono::seconds>(now - recv_last_fixation_);
	const UInt delta_res = delta_time.count();
	auto delta = std::max(delta_res, delta_safe);
	auto speed = recv_last_bytes_ / delta;
	return speed;
}

double QVPN::Core::Tools::QVPNSpeedMeter::get_last_send_speed() const
{
	constexpr UInt delta_safe = 1;

	auto now = Clock::now();
	auto delta_time = std::chrono::duration_cast<std::chrono::seconds>(now - send_last_fixation_);
	const UInt delta_res = delta_time.count();
	auto delta = std::max(delta_res, delta_safe);
	auto speed = send_last_bytes_ / delta;
	return speed;
}

double QVPN::Core::Tools::QVPNSpeedMeter::get_average_recv_speed() const
{
	constexpr UInt delta_safe = 1;

	auto now = Clock::now();
	auto delta_time = std::chrono::duration_cast<std::chrono::seconds>(now - recv_first_fixation_);
	const UInt delta_res = delta_time.count();
	auto delta = std::max(delta_res, delta_safe);
	auto avg_speed = recv_total_bytes_ / delta;
	return avg_speed;
}

double QVPN::Core::Tools::QVPNSpeedMeter::get_average_send_speed() const
{
	constexpr UInt delta_safe = 1;

	auto now = Clock::now();
	auto delta_time = std::chrono::duration_cast<std::chrono::seconds>(now - send_first_fixation_);
	const UInt delta_res = delta_time.count();
	auto delta = std::max(delta_res, delta_safe);
	auto avg_speed = send_total_bytes_ / delta;
	return avg_speed;
}
