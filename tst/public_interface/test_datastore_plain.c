/*
 * Copyright 2020, 2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <test_datastore_plain.h>

#include <nxp_iot_agent.h>
#include <nxp_iot_agent_datastore_plain.h>
#include <test_datastore.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static iot_agent_datastore_t datastore = { 0 };

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

TEST_SETUP(DatastorePlain)
{
	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
	agent_status = iot_agent_datastore_plain_init(&datastore, 0);
	TEST_ASSERT_EQUAL_INT(IOT_AGENT_SUCCESS, agent_status);
}


TEST_TEAR_DOWN(DatastorePlain)
{
	iot_agent_datastore_free(&datastore);
}


TEST(DatastorePlain, AntiTearing)
{
	datastore_commit_test(&datastore);
}


TEST(DatastorePlain, WriteViaProtobuf)
{
	datastore_complete_write_via_requests_test(&datastore);
}


TEST(DatastorePlain, InvalidRequest)
{
	datastore_invalid_request(&datastore);
}


TEST(DatastorePlain, CorruptRequest)
{
	datastore_corrupt_request(&datastore);
}


TEST(DatastorePlain, ReadTooMuch)
{
	uint8_t dummy_data[512];
	write_and_commit_contents(&datastore, dummy_data, sizeof(dummy_data));
	datastore_read_too_much(&datastore);
}


TEST_GROUP_RUNNER(DatastorePlain)
{
   RUN_TEST_CASE(DatastorePlain, AntiTearing);
   RUN_TEST_CASE(DatastorePlain, WriteViaProtobuf);
   RUN_TEST_CASE(DatastorePlain, InvalidRequest);
   RUN_TEST_CASE(DatastorePlain, CorruptRequest);
   RUN_TEST_CASE(DatastorePlain, ReadTooMuch);
}
