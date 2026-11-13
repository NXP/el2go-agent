Overview
========

This manual is the API reference for the EdgeLock 2GO (EL2GO) OTA Library and
the Firmware Update Abstraction Layer (FWUAL). The two libraries are
independent of each other and are used together to update the firmware of a
device over the air:

.. list-table::
   :header-rows: 1
   :widths: 22 39 39

   * -
     - EL2GO OTA Library
     - FWUAL
   * - Full name
     - EdgeLock 2GO Over-the-Air (OTA) library
     - Firmware Update Abstraction Layer
   * - Role
     - Talks to the EdgeLock 2GO OTA server: checks for updates, downloads
       update packages in chunks and reports the update outcome.
     - Writes, verifies, activates, confirms and rolls back firmware images
       through the bootloader.
   * - Public headers
     - ``include/ota``
     - ``include/fwual``
   * - Version function
     - ``el2go_ota_get_version()``
     - ``fwual_get_version()``
   * - Does not do
     - Write flash, verify images or decide when to update.
     - Use the network or decide when to update.
   * - Documented in
     - :doc:`api/ota`
     - :doc:`api/fwual`

The two libraries do not call or depend on each other. The application that
uses them (an *OTA agent*) decides when to check for updates, passes each
downloaded chunk from the OTA library to FWUAL, and reboots the device. The
OTA agent is not part of this API reference.

.. only:: xml or not no_dot

   .. graphviz:: overview_components.gv
      :caption: The OTA library and FWUAL are independent; the OTA agent
                application connects them (example with MCUboot as
                bootloader)

Typical update sequence
-----------------------

The numbers below show how an OTA agent combines the two libraries. The
functions are described in :doc:`api/ota` and :doc:`api/fwual`.

#. Connect to the server: ``el2go_ota_init()``, ``el2go_ota_connect()``.
#. Ask for available updates: ``el2go_ota_check_for_updates()``.
#. Prepare the target image: ``fwual_open_session()``,
   ``fwual_prepare_image()``.
#. Download the package: ``el2go_ota_download_package()``. The chunk callback
   of the agent calls ``fwual_write()`` for every chunk.
#. Finish the image: ``fwual_finalize_image()``, ``fwual_verify_image()``,
   ``fwual_commit_session()``, ``fwual_activate()``,
   ``fwual_close_session()``.
#. Store the outcome and reboot: ``el2go_ota_schedule_status_report()``,
   then reboot the device.
#. After the reboot: ``fwual_init()``, then ``fwual_get_state()``. If the state
   is ``FWUAL_STATE_WAITING_CONFIRM``, call ``fwual_confirm()``; any other
   state means that the new image is not running (for example, the bootloader
   rolled back). Then deliver the stored outcome with
   ``el2go_ota_report_pending_status()``.

Further documentation
---------------------

Architecture, the complete update flow, credential handling, the reference
OTA agents, build integration and the pluggable backends are described in
``doc/ota/el2go_ota_lib.md`` in the repository. The same file lists the
current limitations.
