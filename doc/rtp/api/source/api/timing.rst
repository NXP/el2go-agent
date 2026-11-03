Timing
=======

Opt-in API to measure the duration of the internal provisioning sub-phases
(TLS setup, network connection/handshake, CRL retrieval). Disabled by
default with zero runtime overhead; must be explicitly enabled before
calling :c:func:`el2go_rtp_provision`.

el2go_rtp_timing.h
--------------------
.. doxygengroup:: el2go_rtp_timing
   :project: el2go_rtp_lib
   :content-only:
   :members:
