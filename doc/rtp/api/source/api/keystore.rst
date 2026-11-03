Key Store
==========

The keystore abstraction is used by the RTP library to access and manage
cryptographic keys required for authenticating with the EdgeLock 2GO
server and for provisioning secure assets into the EdgeLock Enclave.

A keystore is closely tied to the :doc:`platform` abstraction: the
platform provides the underlying API used to import the provisioned
secure assets into the device's secure storage (e.g. the HSM), while the
keystore exposes those assets to the RTP library in a backend-independent
way.

.. note::
   Although :c:type:`el2go_keystore_type_t` defines both an SSS and a PSA
   backend type, only the PSA (``EL2GO_KEYSTORE_PSA``) keystore type is
   currently supported.

el2go_keystore.h
-----------------
.. doxygengroup:: el2go_keystore
   :project: el2go_rtp_lib
   :content-only:
   :members:
