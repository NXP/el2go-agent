# Copyright 2020-2021,2023-2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# TODO: Get rid of -Wno-format -Wno-format-security

IF(CMAKE_COMPILER_IS_GNUCC)
  ADD_DEFINITIONS("-Wno-unused-function -Wno-format -Wno-format-security")
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    INCLUDE(${SIMW_TOP_DIR}/ext/core-json.cmake)
ENDIF()

###################### nxp_iot_agent_demo

PROJECT(nxp_iot_agent_demo)

INCLUDE_DIRECTORIES(../inc/)
IF(SSS_HAVE_HOST_WIN10IOT OR SSS_HAVE_HOST_PCWINDOWS)
    INCLUDE_DIRECTORIES(../../ext/)
ENDIF()

IF(SSS_HAVE_HOST_WIN10IOT)

SET(HEADER_FILES
    ../../ext/dirent_win32.h
    ../inc/iot_agent_demo_config.h
    ../inc/iot_agent_claimcode_inject.h
    )

SET(SOURCE_FILES
    iot_agent_demo.c
    )

SET(ASSET_FILES
    ${PROJECT_NAME}_uwp/SmallLogo.png
    ${PROJECT_NAME}_uwp/SmallLogo44x44.png
    ${PROJECT_NAME}_uwp/SplashScreen.png
    ${PROJECT_NAME}_uwp/StoreLogo.png
    ${PROJECT_NAME}_uwp/Logo.png
    )

SET(CONTENT_FILES
    ${PROJECT_NAME}_uwp/package.appxManifest
    )

SET(RESOURCE_FILES
  ${CONTENT_FILES} ${ASSET_FILES}
  ${PROJECT_NAME}_uwp/Windows_TemporaryKey.pfx)

SET_PROPERTY(SOURCE ${CONTENT_FILES} PROPERTY VS_DEPLOYMENT_CONTENT 1)
SET_PROPERTY(SOURCE ${ASSET_FILES} PROPERTY VS_DEPLOYMENT_CONTENT 1)
SET_PROPERTY(SOURCE ${ASSET_FILES} PROPERTY VS_DEPLOYMENT_LOCATION "Assets")

SOURCE_GROUP("Source Files" FILES ${SOURCE_FILES})
SOURCE_GROUP("Header Files" FILES ${HEADER_FILES})
SOURCE_GROUP("Resource Files" FILES ${RESOURCE_FILES})

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} WIN32
    ${SOURCE_FILES}
    ${HEADER_FILES}
    ${RESOURCE_FILES}
)

SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES LINK_FLAGS /SUBSYSTEM:CONSOLE)

ELSE()
FILE(
    GLOB
    iot_agent_demo_files
    ../inc/iot_agent_demo_config.h
    utils/iot_agent_claimcode_inject.c
    utils/iot_agent_claimcode_encrypt.c
    iot_agent_demo.c
)

IF(NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW)
    LIST(REMOVE_ITEM iot_agent_demo_files
        ${CMAKE_CURRENT_SOURCE_DIR}/utils/iot_agent_claimcode_encrypt.c)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
SET(HEADER_FILES
    ../inc/iot_agent_mqtt_paho.h
    )
    LIST(
        APPEND
        iot_agent_demo_files
        utils/iot_agent_mqtt_paho.c
    )
    TARGET_INCLUDE_DIRECTORIES(
        nxp_iot_agent
        PUBLIC
    )
    add_definitions(-DNXP_IOT_AGENT_USE_COREJSON)
ENDIF()

IF(SSS_HAVE_HOST_FRDMK64F OR SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
    FILE(
        GLOB
        iot_agent_demo_port_files
        ../inc/iot_agent_network.h
        network/iot_agent_network_lwip.c
        utils/iot_agent_mqtt_freertos.c
    )
    add_definitions(-DNXP_IOT_AGENT_USE_MBEDTLS_TRANSPORT_FOR_MQTT -DNXP_IOT_AGENT_USE_COREJSON)
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    FILE(
        GLOB
        iot_agent_demo_port_files
        ../inc/iot_agent_network.h
        network/iot_agent_network_lpc_mwm.c
        utils/iot_agent_mqtt_freertos.c
    )
    add_definitions(-DNXP_IOT_AGENT_USE_MBEDTLS_TRANSPORT_FOR_MQTT -DNXP_IOT_AGENT_USE_COREJSON)
ENDIF()

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE}
    ${iot_agent_demo_files}
    ${iot_agent_demo_port_files}
)
ENDIF()

IF(BUILD_SHARED_LIBS)
    IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
                paho-mqtt3cs
        )
    ENDIF()
ELSE()
    IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
                paho-mqtt3cs-static
        )
    ENDIF()
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        core_json
    )
ENDIF()

IF(SSS_HAVE_APPLET_SE05X_IOT AND NOT SSS_HAVE_MBEDTLS_ALT_PSA)
TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    SSS_APIs
)
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    nxp_iot_agent
)


IF(((SSS_HAVE_HOST_PCWINDOWS) OR (SSS_HAVE_HOST_PCLINUX64)) AND (SSS_HAVE_APPLET_NONE) AND (SSS_HAVE_HOSTCRYPTO_MBEDTLS) AND (SSS_HAVE_MBEDTLS_ALT_PSA))
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        mbedtls_psa
    )
ENDIF()

CREATE_BINARY(${PROJECT_NAME})

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()

###################### claimcode_inject

IF(SSS_HAVE_HOSTCRYPTO_OPENSSL AND SSS_HAVE_APPLET_SE05X_IOT)
    PROJECT(claimcode_inject)

SET(HEADER_FILES
    ../inc/iot_agent_claimcode_inject.h
    )

ADD_EXECUTABLE(${PROJECT_NAME}
     utils/iot_agent_claimcode_inject.c
     apps/claimcode_inject_demo.c
   )

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        nxp_iot_agent
        SSS_APIs
    )
    CREATE_BINARY(${PROJECT_NAME})
ENDIF()

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()

###################### remote_provisioning_client

IF(SSS_HAVE_APPLET_SE05X_IOT)
    PROJECT(remote_provisioning_client)

   ADD_EXECUTABLE(${PROJECT_NAME}
        apps/remote_provisioning_client.c
    )

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        SSS_APIs
        rtp_client
        nxp_iot_agent
    )

    CREATE_BINARY(${PROJECT_NAME})
ENDIF()


###################### remote_provisioning_client_lib

IF(SSS_HAVE_APPLET_SE05X_IOT)
    PROJECT(rtp_client)

    IF(SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_IMXLINUX)
        FIND_PACKAGE(Threads)
    ENDIF()

    IF(SSS_HAVE_HOST_FRDMK64F)
        FILE(
            GLOB
            iot_agent_demo_port_files
            ../inc/iot_agent_network.h
            network/iot_agent_network_lwip.c
        )
    ENDIF()

    IF(SSS_HAVE_HOST_LPCXPRESSO55S)
        FILE(
            GLOB
            iot_agent_demo_port_files
            ../inc/iot_agent_network.h
            network/iot_agent_network_lpc_mwm.c
        )
    ENDIF()

    IF(SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
        FILE(
            GLOB
            iot_agent_demo_port_files
            ../inc/iot_agent_network.h
            network/iot_agent_network_lwip.c
        )
    ENDIF()

    SET(HEADER_FILES
        ../inc/iot_agent_rtp_client.h
    )

   ADD_LIBRARY(rtp_client STATIC ${KSDK_STARTUP_FILE}
        utils/iot_agent_rtp_client.c
        ${iot_agent_demo_port_files}
    )

    IF (WIN32)
        SET(LIBS_SYSTEM ws2_32)
    ENDIF()

    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        SSS_APIs
        nxp_iot_agent
        ${LIBS_SYSTEM}
    )

ENDIF()

# all other projects are internal development/debugging and testing tools
IF(NXPInternal)

    ###################### object_dump

    IF(SSS_HAVE_APPLET_SE05X_C AND SSS_HAVE_HOSTCRYPTO_OPENSSL)
        PROJECT(object_dump)

        ADD_EXECUTABLE(${PROJECT_NAME}
            apps/object_dump.c
        )

        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            SSS_APIs
            nxp_iot_agent
        )

        CREATE_BINARY(${PROJECT_NAME})
    ENDIF()


    ###################### nxp_iot_agent_fill_datastore

    IF((SSS_HAVE_APPLET_SE05X_IOT OR SSS_HAVE_MBEDTLS_ALT_PSA) AND (SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX64 OR SSS_HAVE_HOST_IMXLINUX))
        PROJECT(nxp_iot_agent_fill_datastore)

        ADD_EXECUTABLE(${PROJECT_NAME}
            apps/iot_agent_fill_datastore.c
        )

        IF(SSS_HAVE_APPLET_SE05X_IOT)
            TARGET_LINK_LIBRARIES(
                ${PROJECT_NAME}
                SSS_APIs
            )
        ENDIF()

        IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
            IF (SSS_HAVE_MBEDTLS_ALT_PSA)
                TARGET_LINK_LIBRARIES(
                    ${PROJECT_NAME}
                    mbedtls_psa
                )
            ELSE()
            TARGET_LINK_LIBRARIES(
                ${PROJECT_NAME}
                mbedtls
            )
            ENDIF()
        ENDIF()

        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            nxp_iot_agent
        )

        CREATE_BINARY(${PROJECT_NAME})
    ENDIF()

    ###################### remote_runner_server

    IF(((NOT((SSS_HAVE_HOST_LINUX_LIKE OR SSS_HAVE_HOST_PCWINDOWS) AND SSS_HAVE_HOSTCRYPTO_MBEDTLS))
        AND (SSS_HAVE_APPLET_SE05X_A OR SSS_HAVE_APPLET_SE05X_B OR SSS_HAVE_APPLET_SE05X_C OR SSS_HAVE_APPLET_SE050_E))
	    OR ((SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX) AND SSS_HAVE_HOSTCRYPTO_MBEDTLS AND SSS_HAVE_APPLET_NONE))
		PROJECT(remote_runner_server)

		IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
			FILE(
				GLOB
				iot_agent_remote_runner_files
				apps/remote_runner_server.c
				utils/iot_agent_mqtt_paho.c
			)
			add_definitions(-DNXP_IOT_AGENT_USE_COREJSON)
		ENDIF()

		IF(SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_IMXLINUX)
			FIND_PACKAGE(Threads)
		ENDIF()

		IF(SSS_HAVE_HOST_FRDMK64F OR SSS_HAVE_HOST_EVKMIMXRT1060 OR SSS_HAVE_HOST_EVKMIMXRT1170)
			FILE(
				GLOB
				iot_agent_remote_runner_files
				apps/remote_runner_server.c
				network/iot_agent_network_lwip.c
				utils/iot_agent_mqtt_freertos.c
			)
			add_definitions(-DNXP_IOT_AGENT_USE_MBEDTLS_TRANSPORT_FOR_MQTT -DNXP_IOT_AGENT_USE_COREJSON)
		ENDIF()

		IF(SSS_HAVE_HOST_LPCXPRESSO55S)
			FILE(
				GLOB
				iot_agent_remote_runner_files
				apps/remote_runner_server.c
				network/iot_agent_network_lpc_mwm.c
				utils/iot_agent_mqtt_freertos.c
				utils/serial_mwm_server.c
			)
			add_definitions(-DNXP_IOT_AGENT_USE_MBEDTLS_TRANSPORT_FOR_MQTT -DNXP_IOT_AGENT_USE_COREJSON)
		ENDIF()

		IF ((SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX) AND SSS_HAVE_HOSTCRYPTO_MBEDTLS AND SSS_HAVE_APPLET_NONE)
			FILE(
				GLOB
				iot_agent_remote_runner_files
				apps/remote_runner_server.c
			)
			FILE(
				GLOB
				psa_init_files
				${SIMW_TOP_DIR}/nxp_iot_agent/ex/inc/mbedtls_psa/*.h
				utils/mbedtls_psa/psa_init_utils.c
				utils/iot_agent_claimcode_encrypt.c
				)
		ENDIF()


		ADD_EXECUTABLE(${PROJECT_NAME}
			${KSDK_STARTUP_FILE}
			${iot_agent_remote_runner_files}
			${psa_init_files}
		)

		IF(BUILD_SHARED_LIBS)
			IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
				TARGET_LINK_LIBRARIES(
					${PROJECT_NAME}
					paho-mqtt3cs
				)
			ENDIF()
		ELSE()
			IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
				TARGET_LINK_LIBRARIES(
					${PROJECT_NAME}
					paho-mqtt3cs-static
				)
			ENDIF()
		ENDIF()

		IF(SSS_HAVE_HOSTCRYPTO_OPENSSL)
			TARGET_LINK_LIBRARIES(
				${PROJECT_NAME}
				core_json
			)
		ENDIF()

		IF (WIN32)
			SET(LIBS_SYSTEM ws2_32)
		ENDIF()

		TARGET_LINK_LIBRARIES(
			${PROJECT_NAME}
			nxp_iot_agent
			${LIBS_SYSTEM}
		)

        IF(SSS_HAVE_APPLET_SE05X_IOT)
			TARGET_LINK_LIBRARIES(
				${PROJECT_NAME}
				rtp_client
				SSS_APIs
			)
		ENDIF()

		TARGET_COMPILE_DEFINITIONS(
			${PROJECT_NAME}
			PRIVATE PB_FIELD_32BIT
		)

		CREATE_BINARY(${PROJECT_NAME})
	ENDIF()

    IF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-address-of-packed-member
        PRIVATE -Wno-incompatible-pointer-types
        )
    ENDIF()

    ###################### apdu player with stdin/stdout interface

   IF(SSS_HAVE_APPLET_SE05X_IOT AND (SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX64))
        PROJECT(apdu_player_stdin)

        ADD_EXECUTABLE(${PROJECT_NAME}
            apps/apdu_player_stdin.c
        )

        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            SSS_APIs
            ex_common
            smCom
        )

        CREATE_BINARY(${PROJECT_NAME})
    ENDIF()


    ###################### apdu player with stdin/stdout interface, selected and authenticated to
    # card manager (note, only build with platform SCP enabled, as the SCP03 code is required for
    # authentication to the card manager).

    IF(SSS_HAVE_APPLET_SE05X_IOT AND SSS_HAVE_SE05X_AUTH_PLATFSCP03
            AND (SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX64))

            PROJECT(apdu_player_stdin_card_manager)

            ADD_EXECUTABLE(${PROJECT_NAME}
                apps/apdu_player_stdin_card_manager.c
            )

            TARGET_LINK_LIBRARIES(
                ${PROJECT_NAME}
                SSS_APIs
                ex_common
                smCom
            )

            CREATE_BINARY(${PROJECT_NAME})
        ENDIF()


    IF("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-address-of-packed-member
        PRIVATE -Wno-incompatible-pointer-types
        )
    ENDIF()


    ####################################################################################

    IF(SSS_HAVE_MBEDTLS_ALT_PSA)

        PROJECT(psa_tls_client_example)

        FILE(
            GLOB
            MBEDTLS_PROJECT_SOURCE
            apps/psa_examples/psa_tls_client_example.c
            ${SIMW_TOP_DIR}/nxp_iot_agent/ex/inc/mbedtls_psa/*.h
            ${SIMW_TOP_DIR}/nxp_iot_agent/ex/src/utils/mbedtls_psa/*.c
        )

        ADD_EXECUTABLE(${PROJECT_NAME}
            ${MBEDTLS_PROJECT_SOURCE}
        )

        INCLUDE_DIRECTORIES(
            ${PROJECT_NAME}
            ${SIMW_TOP_DIR}/ext/mbedtls/include
            ${SIMW_TOP_DIR}/nxp_iot_agent/inc
            ${SIMW_TOP_DIR}/nxp_iot_agent/src/protobuf
            ../inc/mbedtls_psa
        )
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            nxp_iot_agent
            mbedtls_psa
        )


        CREATE_BINARY(${PROJECT_NAME})

    ####################################################################################

        PROJECT(psa_usage_example)

        FILE(
            GLOB
            MBEDTLS_PROJECT_SOURCE
            apps/psa_examples/psa_usage_example.c
        )

        ADD_EXECUTABLE(${PROJECT_NAME}
            ${MBEDTLS_PROJECT_SOURCE}
        )

        INCLUDE_DIRECTORIES(
            ${PROJECT_NAME}
            ${SIMW_TOP_DIR}/ext/mbedtls/include
            ../inc/mbedtls_psa
        )
        TARGET_LINK_LIBRARIES(
            ${PROJECT_NAME}
            mbedtls_psa
        )

        CREATE_BINARY(${PROJECT_NAME})
		####################################################################################

		PROJECT(nxp_iot_agent_psa_init_keystore)

		FILE(
			GLOB
			MBEDTLS_PROJECT_SOURCE
			apps/psa_examples/nxp_iot_agent_psa_init_keystore.c
			utils/mbedtls_psa/psa_init_utils.c
		)

		ADD_EXECUTABLE(${PROJECT_NAME}
			${MBEDTLS_PROJECT_SOURCE}
		)

		INCLUDE_DIRECTORIES(
			${PROJECT_NAME}
			${SIMW_TOP_DIR}/ext/mbedtls/include
            ../inc/mbedtls_psa
		)
		TARGET_LINK_LIBRARIES(
			${PROJECT_NAME}
			mbedtls_psa
		)

		CREATE_BINARY(${PROJECT_NAME})

    ENDIF(SSS_HAVE_MBEDTLS_ALT_PSA)

ENDIF() # NXPInternal

