Built-in Certificates
======================

This section documents the compile-time, DER-encoded trusted root CA
certificates built into the EdgeLock 2GO RTP library, used to verify the
EdgeLock 2GO server's certificate during the TLS handshake. Separate
certificates (ECC and RSA) are provided for the production and sandbox
environments. The sandbox environment is an internal NXP test server and
is not intended to be used by external users; it is only used during NXP
internal development and testing.

.. note::
   These certificates are not meant to be modified by the user. They are
   only updated when the EdgeLock 2GO server's certificates change.

el2go_rtp_certificates.h
---------------------------
.. doxygengroup:: el2go_rtp_certs
   :project: el2go_rtp_lib
   :content-only:
   :members:

These ECDH public keys are used to encrypt a claim code -- used to
authenticate a device to the EdgeLock 2GO server and bind it to a
specific EdgeLock 2GO account -- before it is transmitted to the server.
They are not used by the RTP library itself; instead, they are consumed
by some Zephyr applications (e.g. the claim code encryption application)
that prepare the claim code ahead of provisioning.

el2go_rtp_claimcode.h
-----------------------
.. doxygengroup:: el2go_rtp_claimcode
   :project: el2go_rtp_lib
   :content-only:
   :members:

