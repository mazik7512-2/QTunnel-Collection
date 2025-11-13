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