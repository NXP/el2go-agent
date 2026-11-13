EL2GO OTA Library API
=====================

The EL2GO OTA Library connects the device to the EdgeLock 2GO OTA server over
a mutually authenticated TLS (mTLS) connection. It checks for available
updates, downloads update packages in chunks and reports the update outcome to
the server. It does not write to flash and does not verify images: the calling
application passes each downloaded chunk to FWUAL (see :doc:`fwual`).

The public headers are located under ``include/ota``.

el2go_ota_lib.h
-----------------
.. doxygengroup:: el2go_ota_lib
   :project: el2go_ota_lib
   :content-only:
   :members:

el2go_ota_certificates.h
---------------------------
.. doxygengroup:: el2go_ota_certs
   :project: el2go_ota_lib
   :content-only:
   :members:

el2go_ota_config.h
---------------------
.. doxygengroup:: el2go_ota_config
   :project: el2go_ota_lib
   :content-only:
   :members:
