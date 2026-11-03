Overview
========

This documentation describes the EdgeLock 2GO RTP (Remote Trust Provisioning) library
API.

The EdgeLock 2GO RTP library is used to connect a device to the EdgeLock
2GO server, and to download and provision secure assets into the device's
secure storage (e.g. the EdgeLock Enclave). Secure assets include keys,
certificates and other sensitive device credentials that are required for
the device to operate securely in the field. The library currently
supports Linux and Zephyr as target operating systems.

Typical responsibilities of the EdgeLock 2GO RTP library include:

* Establishing a mutually authenticated TLS (mTLS) connection to the
  EdgeLock 2GO server.
* Authenticating the device using its claim code (if one provided)
* Downloading the secure assets assigned to the device
* Provisioning the downloaded assets into the device's secure storage
  (e.g. the EdgeLock Enclave)

The library is built around a set of pluggable components, so that it can
be adapted to different hardware and deployment needs:

.. only:: xml or not no_dot

   .. graphviz:: overview_components.gv
      :caption: RTP library pluggable components overview (example using
                mbedTLS as transport and PSA as keystore type)

* :doc:`api/platform` -- abstracts access to the underlying secure
  hardware (e.g. HSM). Two backends are currently supported: SMW (for
  MPUs running Linux) and ELS PKC (for MCUs with the EdgeLock Secure
  Enclave, used in Zephyr builds).
* :doc:`api/keystore` -- exposes provisioned cryptographic keys and
  secure assets to the RTP library in a backend-independent way,
  regardless of which platform backend stores them. Currently, only
  keystores of type PSA are supported.
* **Transport/TLS** -- the mutually authenticated TLS (mTLS) connection
  to the EdgeLock 2GO server is currently implemented using mbedTLS, but
  the library was designed so that this layer can be replaced with a
  different TLS implementation.
* :doc:`api/datastore` -- persists non-secret data (e.g. server
  connection details) using a transactional, two-slot read/write scheme;
  file system, plain memory and fully custom backends are supported.

The public headers documented here are located under ``include/rtp`` and
``include/common``.

.. note::
   For more details on how to set up secure objects on the EdgeLock 2GO
   server, or about claim codes, refer to the EdgeLock 2GO server
   documentation.
