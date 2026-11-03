Overview
========

This documentation covers the Over-the-Air (OTA) update agent of the
NXP IoT Agent (EdgeLock 2GO / EL2GO) client stack.

The OTA agent is responsible for downloading, validating and applying
firmware updates on the device, built on top of the Firmware Update
Abstraction Layer (FWUAL).

Public headers for the OTA agent and FWUAL are located under
``include/ota`` and ``include/fwual``, and are automatically documented
in the :doc:`api/ota` and :doc:`api/fwual` sections via Doxygen and
Breathe.

.. note::
   Documentation for the RTP (Remote Trust Provisioning) agent is built
   separately; see ``doc/rtp/`` for the corresponding CMake target.
