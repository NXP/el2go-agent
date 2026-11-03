Data Store
===========

The datastore abstraction is used by the RTP library to persist
non-secret data. A datastore uses a transactional, two-slot
(double-buffered) read/write approach: writes go to one slot while the
previously committed slot remains available for reading, and a commit
operation atomically swaps the slots. This protects the stored data
against corruption if a write is interrupted (e.g. by a power loss).

Internally, the library only uses a datastore for one purpose: storing
the connection details for the EdgeLock 2GO server (hostname, port, and
server certificate). This special datastore is identified by the
reserved ID ``EL2GO_RTP_DATASTORE_EDGELOCK_ID`` (see :doc:`configuration`),
and is configured via :c:func:`el2go_rtp_datastore_el2go`.

There are three datastore types currently implemented:

* **File system** (``EL2GO_DATASTORE_TYPE_FS``) -- data is stored in a
  file on disk.
* **Plain** (``EL2GO_DATASTORE_TYPE_PLAIN``) -- data is stored in memory.
* **Custom** (``EL2GO_DATASTORE_TYPE_CUSTOM``) -- the user implements the
  storage logic by providing a set of callback functions
  (:c:type:`el2go_datastore_ops_t`).

el2go_datastore.h
------------------
.. doxygengroup:: el2go_datastore
   :project: el2go_rtp_lib
   :content-only:
   :members:
