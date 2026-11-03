Configuration
==============

This section describes the compile-time configuration parameters for the
EdgeLock 2GO RTP library, defined in ``el2go_rtp_config.h``. These
parameters control datastore/keystore limits, server connection settings
(hostname, port), the client certificate subject, and CRL request behavior,
allowing the library to be tuned to different deployment scenarios.

.. note::
   The EdgeLock 2GO server hostname and port can be set in multiple ways,
   evaluated in the following order of precedence:

   1. At runtime, via the ``config`` parameter passed to
      :c:func:`el2go_rtp_datastore_el2go`.
   2. At build time, via the Kconfig options
      ``CONFIG_EL2GO_RTP_EDGELOCK2GO_HOSTNAME`` and
      ``CONFIG_EL2GO_RTP_EDGELOCK2GO_PORT`` (Zephyr builds).
   3. At build time, by pre-defining the macros
      ``EL2GO_RTP_EDGELOCK2GO_HOSTNAME`` and ``EL2GO_RTP_EDGELOCK2GO_PORT``
      before this header is included.
   4. The compile-time defaults in ``el2go_rtp_config.h`` (a placeholder
      hostname and port 443), used only if none of the above are set.

Most parameters in this file configure the library for the target
deployment and are only expected to change when the EdgeLock 2GO server
account or the device's resource constraints change, such as
``EL2GO_RTP_CLIENT_CERT_MAX_SIZE`` or ``EL2GO_RTP_SUBJECT``. A smaller set
of parameters are intended to be tuned by the user for their specific
use case:

* ``EL2GO_RTP_MAX_DATASTORES``
* ``EL2GO_RTP_MAX_KEYSTORES``
* ``EL2GO_RTP_EDGELOCK2GO_HOSTNAME``
* ``EL2GO_RTP_REQUEST_CRL``

el2go_rtp_config.h
--------------------
.. doxygengroup:: el2go_rtp_config
   :project: el2go_rtp_lib
   :content-only:
   :members:
