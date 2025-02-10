..
    Copyright 2022,2025 NXP

    SPDX-License-Identifier: Apache-2.0


.. highlight:: bat

.. _el2go_usage_examples:

=======================================================================
 SE05X EdgeLock 2GO Agent example
=======================================================================

This demo demonstrates how to use the EdgeLock 2GO service for provisioning keys and certificates into the SE05x secure element.
Those keys and certificates can then be used to establish mutual-authenticated TLS connections to cloud services such as AWS or Azure.

Prerequisites
=======================================================================
- Active EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
- Any Serial communicator


Setup of the EdgeLock 2GO platform
===========================================================================
The documentation which explains how to setup the EdgeLock 2GO Account to
- Add devices to the group
- Create Secure Object
- Assign Secure Objects to device
can be found under the EdgeLock 2GO account under the Documentation tab.


Building the Demo
=======================================================================
Before you start building the demo you must configure the EdgeLock 2GO URL for your account:
the account specific URL can be copied from the EdgeLock 2GO account (in Admin Settings section)
Once the URL is copied, there are different possibilities how to configure it in the EL2GO Agent;
- From EdgeLock 2GO datastore if available and valid (only on Windows and Linux OSs)
- By adding the command line options EDGELOCK2GO_HOSTNAME and EDGELOCK2GO_PORT when executing it (only on Windows and Linux OSs)
- By exporting environment variables EDGELOCK2GO_HOSTNAME and EDGELOCK2GO_PORT (only on Windows and Linux OSs)
- By changing the value of the precompiler definitions EDGELOCK2GO_HOSTNAME and EDGELOCK2GO_PORT
- By changing the value of EDGELOCK2GO_HOSTNAME and EDGELOCK2GO_PORT macros in middleware/se_hostlib/nxp_iot_agent/inc/nxp_iot_agent_config.h
The order of priority is top down, so the command line option will have precedence over environment variables for example. On Windows and Linux OSs
a valid EdgeLock 2GO datastore will be created on the first connection and from that time on will be used since has the highest priority;
if the user wants to reconfigure it using any other method, the EdgeLock 2GO datastore file should be deleted first.
For command line and environment variable options both hostname and port should be defined correctly, otherwise the selected method will not apply.

To build for your platform follow your board specific readme file.

In order to enable MQTT test to cloud services or configuring the device with specific device features, 
refer to the documentation present in the Plug & Trust MW package and which can be downloaded 
from: https://www.nxp.com/products/security-and-authentication/authentication/:SE050?tab=Design_Tools_Tab.


Running the Demo
=======================================================================
If you have built a binary, flash the binary on to the board and reset the board.