Platform
=========

The platform abstraction initializes and manages access to the underlying
secure hardware (e.g. HSM) that the RTP library depends on for
cryptographic operations.

Currently, two platform backends are supported:

* **SMW** (Security Middleware) -- abstracts the API used to import
  secure assets into the EdgeLock Secure Enclave. It is used on MPUs
  running Linux platforms. SMW provides the implementation of the PSA
  crypto library, which is used by the :doc:`keystore` to store the
  provisioned secure assets.

* **ELS PKC** -- platform backend for MCUs with the EdgeLock Secure
  Enclave (ELS) and the PKC crypto accelerator, such as the RW61x
  family. It is used in Zephyr builds. The PSA Crypto API is provided by
  the NXP PSA driver (ELS PKC), and in TF-M builds by the secure side.
  At platform initialization it calls ``psa_crypto_init()``. The platform
  also reports the supported TLS cipher suites (ECDHE-ECDSA/RSA with
  AES-128/256, CBC and GCM, SHA-256/384) and elliptic curves (secp256r1,
  secp384r1, secp521r1). Provisioned secure assets are stored through the
  :doc:`keystore`.

el2go_platform.h
-----------------
.. doxygengroup:: el2go_platform_pub
   :project: el2go_rtp_lib
   :content-only:
   :members:
