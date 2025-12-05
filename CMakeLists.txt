cmake_minimum_required(VERSION 4.1)  # Минимальная версия проекта

# C++
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# Project
set(PROJECT_NAME "QVPN Collection")
project(${PROJECT_NAME}   
	VERSION 0.5
	DESCRIPTION "QVPN Project"
	LANGUAGES CXX
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
file(GLOB_RECURSE _lib_src "${QVPN_LIBRARY_PATH}/*.cpp")
file(GLOB_RECURSE _lib_incl "${QVPN_LIBRARY_PATH}/*.hpp")



# OS files
file(GLOB_RECURSE os_lib_src "${QVPN_LIBRARY_PATH}/${CMAKE_SYSTEM_NAME}/*.cpp")
file(GLOB_RECURSE os_lib_incl "${QVPN_LIBRARY_PATH}/${CMAKE_SYSTEM_NAME}/*.hpp")


# Concat default lib files + os files
set(lib_src "${_lib_src};${os_lib_src}")
set(lib_incl "${_lib_incl};${os_lib_incl}")


# External libs

# Ручное подключение Npcap

set(NPCAP_PATH "${CMAKE_CURRENT_SOURCE_DIR}/include/npcap") # ваш путь
add_definitions(-DNPCAP=ON)
include_directories(${NPCAP_PATH}/Include)
link_directories(${NPCAP_PATH}/Lib/x64)


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

endif()

# Libs
add_library(${QVPN_LIBRARY_NAME} STATIC ${lib_incl} ${lib_src})

# Executables
if(QVPN_BUILD_SERVER OR QVPN_BUILD_ALL)
	message("QVPN Server App is building...")
	file(GLOB_RECURSE server_src "${QVPN_SERVER_APP_PATH}/src/*.cpp")
	add_executable("${QVPN_SERVER_APP_NAME}" ${server_src})
	set_target_properties(${QVPN_SERVER_APP_NAME} PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
	target_link_libraries(${QVPN_SERVER_APP_NAME} PRIVATE ${QVPN_LIBRARY_NAME})
endif()


if(QVPN_BUILD_CLIENT OR QVPN_BUILD_ALL)
	message("QVPN Client App is building...")
	file(GLOB_RECURSE client_src "${QVPN_CLIENT_APP_PATH}/src/*.cpp")
	add_executable("${QVPN_CLIENT_APP_NAME}" ${client_src})
	set_target_properties(${QVPN_CLIENT_APP_NAME} PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
	target_link_libraries(${QVPN_CLIENT_APP_NAME} PRIVATE ${QVPN_LIBRARY_NAME})
endif()


# Определяем целевую директорию вывода 
set(TARGET_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE}")


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

endif()


file(GLOB whitelists_list "${CMAKE_CURRENT_SOURCE_DIR}/*.qwlist")

# Копирование всех белых списков с расширением qwlist
foreach(file_ IN ITEMS ${whitelists_list})

	set(filename, get_filename_component(FILE_NAME ${file_} NAME))

	add_custom_command(
		TARGET ${QVPN_CLIENT_APP_NAME} POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different 
				${file_} 
				${TARGET_DIRECTORY}/${filename} 
		COMMENT "Copying all whitelists to ${TARGET_DIRECTORY} directory\n"
	)

endforeach()
#install(FILES ${WINTUN_DLL_PATH} DESTINATION ${TARGET_DIRECTORY})  # cmake --build . --target install - запуск