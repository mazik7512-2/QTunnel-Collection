cmake_minimum_required(VERSION 4.1)  # Минимальная версия проекта

# C++
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")

# Project
set(PROJECT_NAME "QVPN Collection")
project(${PROJECT_NAME}   
	VERSION 0.5
	DESCRIPTION "QVPN Project"
	LANGUAGES CXX C
)

# Build options

option(QVPN_BUILD_TEST "Build QVPN tests" OFF)

option(QVPN_BUILD_CLIENT "Build QVPN client app only" OFF)
option(QVPN_BUILD_SERVER "Build QVPN server app only" OFF)
option(QVPN_BUILD_LIB "Build QVPN library only" OFF)
option(QVPN_BUILD_ALL "Build QVPN (client and server) apps and lib" ON)


# Settings

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include")



# CMake dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${CMAKE_SYSTEM_NAME}) 
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${CMAKE_SYSTEM_NAME})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/${CMAKE_SYSTEM_NAME})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE})


# QVPN Names
set(QVPN_LIBRARY "QVPN Lib")
set(QVPN_SERVER_APP "QVPN Server App")
set(QVPN_CLIENT_APP "QVPN Client App")

set(QVPN_LIBRARY_NAME "QVPN_Lib")
set(QVPN_SERVER_APP_NAME "QVPN_Server_App")
set(QVPN_CLIENT_APP_NAME "QVPN_Client_App")


# QVPN Data
set(QVPN_LIBRARY_PATH "QVPN/${QVPN_LIBRARY}")
set(QVPN_SERVER_APP_PATH "QVPN/${QVPN_SERVER_APP}")
set(QVPN_CLIENT_APP_PATH "QVPN/${QVPN_CLIENT_APP}")



# Includes
set(PROJ_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/QVPN/${QVPN_LIBRARY}/include")
include_directories(${PROJ_INCLUDE})

# OS Includes
set(OS_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/QVPN/${QVPN_LIBRARY}/include/${CMAKE_SYSTEM_NAME}")
include_directories(${OS_INCLUDE})


# Project Dirs
add_subdirectory("${QVPN_LIBRARY_PATH}")
add_subdirectory("${QVPN_SERVER_APP_PATH}")
add_subdirectory("${QVPN_CLIENT_APP_PATH}")

#Lib files
file(GLOB _lib_src "${QVPN_LIBRARY_PATH}/src/*.cpp")
file(GLOB _lib_incl "${QVPN_LIBRARY_PATH}/include/*.hpp")


# OS files
file(GLOB os_lib_src "${QVPN_LIBRARY_PATH}/src/${CMAKE_SYSTEM_NAME}/*.cpp")
file(GLOB os_lib_incl "${QVPN_LIBRARY_PATH}/include/${CMAKE_SYSTEM_NAME}/*.hpp")


# Concat default lib files + os files
set(lib_src "${_lib_src};${os_lib_src}")
set(lib_incl "${_lib_incl};${os_lib_incl}")


# Определяем целевую директорию вывода 
set(TARGET_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE}")

# External libs

# Ручное подключение Npcap

set(NPCAP_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include/npcap") # ваш путь
add_definitions(-DNPCAP=ON)
include_directories(${NPCAP_PATH}/Include)
link_directories(${NPCAP_PATH}/Lib/x64)


include(FetchContent)

# Arg parse подключение
FetchContent_Declare(
    argparse
    GIT_REPOSITORY https://github.com/p-ranav/argparse.git
)
FetchContent_MakeAvailable(argparse)


if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")

	# Подключение WinTun
	set(WINTUN_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include/wintun")
	include_directories(${WINTUN_PATH}/include)
	link_directories(${WINTUN_PATH}/bin/amd64)


	# Подключение WinDivert
	set(WINDIVERT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include/windivert")
	include_directories(${WINDIVERT_PATH}/include)
	link_directories(${WINDIVERT_PATH}/x64)

	#find_package(PCAP REQUIRED)  # не работает
	#include(FINDPCAP.cmake)  # аналогично

	set(WINTUN_DLL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include/wintun/bin/amd64/wintun.dll")
	set(WINDIVERT_DLL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include/windivert/x64/windivert.dll")
	set(WINDIVERT_DRIVER_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include/windivert/x64/WinDivert64.sys")

elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

endif()

# Libs
add_library(${QVPN_LIBRARY_NAME} STATIC ${lib_incl} ${lib_src})

# json подключение
FetchContent_Declare(
	json 
	URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
)
FetchContent_MakeAvailable(json)

# link json to QVPN library
target_link_libraries(${QVPN_LIBRARY_NAME} PUBLIC nlohmann_json::nlohmann_json)

# whitelists
file(GLOB whitelists_list "${CMAKE_CURRENT_SOURCE_DIR}/*.qwlist")


# Executables
if(QVPN_BUILD_SERVER OR QVPN_BUILD_ALL)

	message("QVPN Server App is building...")
	
	file(GLOB_RECURSE server_inc "${QVPN_SERVER_APP_PATH}/include/*.hpp")
	file(GLOB_RECURSE server_src "${QVPN_SERVER_APP_PATH}/src/*.cpp")
	add_executable("${QVPN_SERVER_APP_NAME}" ${server_inc} ${server_src})

	if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
		set_target_properties(${QVPN_SERVER_APP_NAME} PROPERTIES
			LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
		)

	elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

		

	endif()
	# set working directory for vc
	set_target_properties("${QVPN_SERVER_APP_NAME}" PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE})
	
	# include server app headers
	include_directories("${QVPN_SERVER_APP_PATH}/include")
	
	# link QVPN library
	target_link_libraries(${QVPN_SERVER_APP_NAME} PRIVATE ${QVPN_LIBRARY_NAME})
	# link arg parse library
	target_link_libraries(${QVPN_SERVER_APP_NAME} PRIVATE argparse)
	
	# Подключение sqlite3 к Server App
	set(SQLITE3_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include/sqlite3")

	
	if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")

		
		#include_directories(${SQLITE3_PATH})
		#link_directories(${SQLITE3_PATH})
		target_include_directories(${QVPN_SERVER_APP_NAME} PRIVATE ${SQLITE3_PATH})
		target_link_directories(${QVPN_SERVER_APP_NAME} PRIVATE ${SQLITE3_PATH})

		# Копирование sqlite3.dll
		add_custom_command(
			TARGET ${QVPN_SERVER_APP_NAME} POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different 
					"${SQLITE3_PATH}/sqlite3.dll" 
					"${TARGET_DIRECTORY}/sqlite3.dll" 
			COMMENT "Copying sqlite3.dll ${TARGET_DIRECTORY} directory\n"
			)

	elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

		# Создаем библиотеку из локального файла
		add_library(sqlite3 STATIC ${SQLITE3_PATH}/sqlite3.c)

		# Указываем, где искать заголовочный файл sqlite3.h
		target_include_directories(sqlite3 PUBLIC ${SQLITE3_PATH})

		target_link_libraries(${QVPN_SERVER_APP_NAME} PRIVATE sqlite3)

	endif()
	# Копирование всех белых списков с расширением qwlist для server app
	foreach(file_ IN ITEMS ${whitelists_list})

		add_custom_command(
			TARGET ${QVPN_SERVER_APP_NAME} POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different 
					${file_} 
					${TARGET_DIRECTORY}/${filename} 
			COMMENT "Copying ${file_} to ${TARGET_DIRECTORY} directory\n"
		)

	endforeach()
	
	
	set(server_settings "${CMAKE_CURRENT_SOURCE_DIR}/server_settings_example.json")

	# Копирование шаблонного файла с настройками
	add_custom_command(
		TARGET ${QVPN_SERVER_APP_NAME} POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different 
				${server_settings} 
				"${TARGET_DIRECTORY}/server_settings.json" 
		COMMENT "Copying server settings ${TARGET_DIRECTORY} directory\n"
		)
	
	
	set(database_path "${CMAKE_CURRENT_SOURCE_DIR}/db_example.sqlite3")
	
	# Копирование базы данных
	add_custom_command(
		TARGET ${QVPN_SERVER_APP_NAME} POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different 
				${database_path} 
				"${TARGET_DIRECTORY}/server_database.sqlite3" 
		COMMENT "Copying database ${TARGET_DIRECTORY} directory\n"
		)
endif()


if(QVPN_BUILD_CLIENT OR QVPN_BUILD_ALL)
	message("QVPN Client App is building...")
	file(GLOB_RECURSE client_src "${QVPN_CLIENT_APP_PATH}/src/*.cpp")
	add_executable("${QVPN_CLIENT_APP_NAME}" ${client_src})
	set_target_properties(${QVPN_CLIENT_APP_NAME} PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
	
	# set working directory for vs
	set_target_properties("${QVPN_CLIENT_APP_NAME}" PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE})
	
	# link QVPN Library
	target_link_libraries(${QVPN_CLIENT_APP_NAME} PRIVATE ${QVPN_LIBRARY_NAME})
	# link arg parse library
	target_link_libraries(${QVPN_CLIENT_APP_NAME} PRIVATE argparse)
	
	# Копирование всех белых списков с расширением qwlist для client app
	foreach(file_ IN ITEMS ${whitelists_list})

		add_custom_command(
			TARGET ${QVPN_CLIENT_APP_NAME} POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy_if_different 
					${file_} 
					"${TARGET_DIRECTORY}/${filename}" 
			COMMENT "Copying ${file_} to ${TARGET_DIRECTORY} directory\n"
		)

	endforeach()

	set(client_settings "${CMAKE_CURRENT_SOURCE_DIR}/client_settings_example.json")

	# Копирование шаблонного файла с настройками
	add_custom_command(
		TARGET ${QVPN_CLIENT_APP_NAME} POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different 
				${client_settings} 
				"${TARGET_DIRECTORY}/client_settings.json" 
		COMMENT "Copying client settings ${TARGET_DIRECTORY} directory\n"
		)
	
endif()


if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
	# Копирование dll wintun
	add_custom_command(
		TARGET ${QVPN_LIBRARY_NAME} POST_BUILD 
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${WINTUN_DLL_PATH}
				${TARGET_DIRECTORY}/wintun.dll
		COMMENT "Copying wintun.dll to ${TARGET_DIRECTORY} directory\n"
	)


	# Копирование dll windivert
	add_custom_command(
		TARGET ${QVPN_LIBRARY_NAME} POST_BUILD 
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${WINDIVERT_DLL_PATH}
				${TARGET_DIRECTORY}/windivert.dll
		COMMENT "Copying windivert.dll to ${TARGET_DIRECTORY} directory\n"
	)

	# Копирование драйвера windivert
	add_custom_command(
		TARGET ${QVPN_LIBRARY_NAME} POST_BUILD 
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
				${WINDIVERT_DRIVER_PATH}
				${TARGET_DIRECTORY}/WinDivert64.sys
		COMMENT "Copying WinDivert64.sys to ${TARGET_DIRECTORY} directory\n"
	)

elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")



endif()

#install(FILES ${WINTUN_DLL_PATH} DESTINATION ${TARGET_DIRECTORY})  # cmake --build . --target install - запуск