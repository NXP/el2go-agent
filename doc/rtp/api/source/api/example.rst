Example
========

This example shows the typical sequence of calls to provision a device
using the EdgeLock 2GO RTP library: initialize the agent and the
platform, initialize and register a keystore and a datastore, configure
the EdgeLock 2GO connection, run the provisioning exchange, and clean up.

.. code-block:: c

   /* EdgeLock 2GO RTP provisioning example */
   #include "rtp/el2go_rtp.h"
   #include "rtp/el2go_rtp_config.h"
   #include "common/el2go_platform.h"
   #include "common/el2go_keystore.h"
   #include "common/el2go_datastore.h"

   #define EL2GO_DATASTORE_NAME "edgelock2go_datastore.bin"

   el2go_status_t example_provision(void)
   {
       el2go_status_t status;
       el2go_rtp_ctx_t *agent_ctx = NULL;
       el2go_platform_ctx_t *platform_ctx = NULL;
       el2go_keystore_t keystore_ctx = { 0 };
       el2go_datastore_t datastore_ctx = { 0 };
       el2go_rtp_datastore_config_t el2go_config = { 0 };
       void *report = NULL;

       /* 1. Initialize the RTP agent context. */
       status = el2go_rtp_init(&agent_ctx);
       if (status != EL2GO_STATUS_SUCCESS) {
           return status;
       }

       /* 2. Initialize the platform abstraction (e.g. SMW, ELS PKC). This
        *    gives access to the device's secure storage. */
       status = el2go_platform_init(&platform_ctx);
       if (status != EL2GO_STATUS_SUCCESS) {
           goto free_agent;
       }

       /* 3. Initialize the keystore (currently PSA-backed) on top of the
        *    platform, and register it with the agent. */
       status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID,
                                     platform_ctx, &keystore_ctx);
       if (status != EL2GO_STATUS_SUCCESS) {
           goto free_platform;
       }

       status = el2go_rtp_add_keystore(agent_ctx, &keystore_ctx);
       if (status != EL2GO_STATUS_SUCCESS) {
           goto free_keystore;
       }

       /* 4. Initialize the special EdgeLock 2GO datastore (file-system
        *    backed here) and register it with the agent. */
       status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID,
                                      EL2GO_DATASTORE_NAME,
                                      EL2GO_DATASTORE_TYPE_FS,
                                      &datastore_ctx, NULL);
       if (status != EL2GO_STATUS_SUCCESS) {
           goto remove_keystore;
       }

       status = el2go_rtp_add_datastore(agent_ctx, &datastore_ctx);
       if (status != EL2GO_STATUS_SUCCESS) {
           goto free_datastore;
       }

       /* 5. Configure the EdgeLock 2GO server connection on the
        *    datastore. The config pointer must not be NULL. Fields left
        *    unset (zero) fall back to the compile-time defaults from
        *    el2go_rtp_config.h: the hostname and port are only taken from
        *    the config when both are set, and the server certificate is
        *    only taken from the config when it is provided. */
       status = el2go_rtp_datastore_el2go(&datastore_ctx, &keystore_ctx,
                                           &el2go_config);
       if (status != EL2GO_STATUS_SUCCESS) {
           goto remove_datastore;
       }

       /* 6. Connect to the EdgeLock 2GO server and provision the secure
        *    assets assigned to this device. */
       status = el2go_rtp_provision(agent_ctx, &report);

       /* 7. Optionally inspect and release the provisioning report. */
       if (report != NULL) {
           el2go_rtp_print_status_report(report);
           el2go_rtp_free_status_report(&report);
       }

   remove_datastore:
       el2go_rtp_remove_datastore(agent_ctx, &datastore_ctx);
   free_datastore:
       el2go_datastore_free(&datastore_ctx);
   remove_keystore:
       el2go_rtp_remove_keystore(agent_ctx, &keystore_ctx);
   free_keystore:
       el2go_keystore_free(&keystore_ctx);
   free_platform:
       el2go_platform_free(&platform_ctx);
   free_agent:
       el2go_rtp_free(&agent_ctx);

       return status;
   }

.. note::
   For details on how to assign secure objects or claim codes to a device
   on the EdgeLock 2GO server, refer to the EdgeLock 2GO server
   documentation.
