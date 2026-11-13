FWUAL (Firmware Update Abstraction Layer) API
=============================================

FWUAL provides a bootloader-independent interface to write, verify, activate,
confirm and roll back firmware images. It does not use the network and does
not depend on the EL2GO OTA Library (see :doc:`ota`): the calling application
supplies the image data.

The public headers are located under ``include/fwual``.

The device-level update state is persisted and survives a reboot or a power
loss. The states follow this lifecycle (see ``fwual_state_t``):

.. code-block:: text

   IDLE -> WRITING -> STAGED -> COMMITTED -> REBOOT_REQUIRED ->
   WAITING_CONFIRM -> ACTIVE

   Failure states: FAILED, ROLLED_BACK

The MCUboot backend, currently the only backend, does not report ``WRITING``
and ``STAGED``: the state changes from ``IDLE`` directly to ``COMMITTED`` when
the session is committed. An application should still handle all states,
because other backends can report them. The complete update flow is described
in ``doc/ota/el2go_ota_lib.md`` in the repository.

fwual.h
-------
.. doxygengroup:: fwual
   :project: el2go_ota_lib
   :content-only:
   :members:

fwual_types.h
---------------
.. doxygengroup:: fwual_types
   :project: el2go_ota_lib
   :content-only:
   :members:
