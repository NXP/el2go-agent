/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __FWUAL_H__
#define __FWUAL_H__

#include "fwual/fwual_types.h"

/**
 * @brief Initializes the FWUAL backend
 *
 * Idempotent - safe to call multiple times without side effects. Prepares
 * persistent state storage and restores any interrupted update session from
 * NVM so that fwual_get_state() reflects the correct state immediately after
 * this call returns.
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_PLATFORM if the backend cannot be initialized
 */
fwual_result_t fwual_init(void);

/**
 * @brief Queries device-level constraints and capabilities
 *
 * Returns time-invariant properties of the current backend for this boot.
 * The OTA Agent SHOULD call this once after fwual_init() and cache the result
 * for the duration of the update session.
 *
 * @param[out] out_caps Pointer to a fwual_caps_t structure to populate
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_INVALID_PARAM if out_caps is NULL
 */
fwual_result_t fwual_get_caps(fwual_caps_t *out_caps);

/**
 * @brief Opens a new firmware update session
 *
 * Allocates and initializes a session context. Only one session may be active
 * at a time unless the backend explicitly documents multi-session support.
 * The returned handle must be passed to all subsequent session-scoped API
 * calls and released via fwual_close_session().
 *
 * @param[out] out_session Receives the opaque session handle upon success
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_INVALID_PARAM if out_session is NULL
 * @retval FWUAL_ERR_BUSY if a session is already active
 */
fwual_result_t fwual_open_session(fwual_session_t **out_session);

/**
 * @brief Closes a session and releases its resources
 *
 * If called before fwual_commit_session(), any staged images are discarded
 * and the device update state is left unchanged (no partial update is
 * applied). Safe to call from any session state for cleanup purposes,
 * including error recovery paths.
 *
 * @param[in] session Session handle returned by fwual_open_session()
 *
 * @retval FWUAL_OK upon success
 */
fwual_result_t fwual_close_session(fwual_session_t *session);

/**
 * @brief Declares an image to be updated in this session
 *
 * Provisions storage (flash slot, partition, etc.) and readies the target for
 * writing. Must be called exactly once per image before any fwual_write()
 * calls for that image. Multiple images may be prepared within a single
 * session for atomic multi-image updates.
 *
 * The size, hash_algo, expected_hash, and hash_len fields of desc are used
 * during fwual_verify_image(). The pointed-to data must remain valid until
 * fwual_close_session() or fwual_commit_session().
 *
 * @param[in] session Active session handle
 * @param[in] desc Image metadata. Must not be NULL
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_INVALID_PARAM if session or desc is NULL
 * @retval FWUAL_ERR_INVALID_STATE if no session is open
 * @retval FWUAL_ERR_NO_SPACE if storage is insufficient
 * @retval FWUAL_ERR_UNSUPPORTED if image_id is unknown to the backend or
 *   update_type is FWUAL_UPDATE_DELTA on a backend without delta support
 */
fwual_result_t fwual_prepare_image(fwual_session_t *session,
                   const fwual_image_desc_t *desc);

/**
 * @brief Optional early capacity check for a prepared image
 *
 * Allows the OTA Agent to verify that sufficient storage is available for a
 * previously prepared image before committing to the full download. This is
 * an advisory check; fwual_prepare_image() also enforces capacity.
 *
 * @param[in] session Active session handle
 * @param[in] image_id Target image identifier (must have been prepared)
 *
 * @retval FWUAL_OK if sufficient storage is available
 * @retval FWUAL_ERR_NO_SPACE if capacity is insufficient
 */
fwual_result_t fwual_check_storage(fwual_session_t *session,
                   fwual_image_id_t image_id);

/**
 * @brief Cancels a prepared image and discards its staged data
 *
 * Releases storage reserved for the specified image and removes it from the
 * session. Does not affect other images prepared in the same session. After
 * this call, fwual_prepare_image() may be called again for the same image_id
 * within the same session.
 *
 * @param[in] session Active session handle
 * @param[in] image_id Target image identifier
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_INVALID_STATE if the image was not prepared in this session
 */
fwual_result_t fwual_cancel_image(fwual_session_t *session,
                  fwual_image_id_t image_id);

/**
 * @brief Writes a contiguous block of image data at a logical offset
 *
 * Writes len bytes from data into the storage slot for image_id at logical
 * byte offset. FWUAL maps the logical offset to the physical storage location;
 * the caller does not need to know the underlying flash layout.
 *
 * If fwual_caps_t::requires_sequential_writes is true, writes for a given
 * image MUST be strictly monotonically increasing in offset. An out-of-order
 * write returns FWUAL_ERR_INVALID_STATE.
 *
 * @param[in] session Active session handle
 * @param[in] image_id Target image identifier (must have been prepared)
 * @param[in] offset Byte offset within the logical image (0-based)
 * @param[in] data Pointer to the data buffer to write
 * @param[in] len Number of bytes to write
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_INVALID_PARAM if data is NULL, len is 0, or offset + len
 *   exceeds the declared image size
 * @retval FWUAL_ERR_INVALID_STATE if the image was not prepared or the write
 *   is out-of-order when sequential writes are required
 * @retval FWUAL_ERR_IO upon storage write failure
 */
fwual_result_t fwual_write(fwual_session_t *session, fwual_image_id_t image_id,
               uint64_t offset, const uint8_t *data, size_t len);

/**
 * @brief Signals that all data for an image has been written
 *
 * Flushes any internal write buffers and closes the image write stream. Must
 * be called after the last fwual_write() for an image and before
 * fwual_verify_image(). After this call, no further fwual_write() calls are
 * permitted for this image in the current session.
 *
 * @param[in] session Active session handle
 * @param[in] image_id Target image identifier
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_INVALID_STATE if the image was not prepared or the total
 *   bytes written do not match the declared image size
 */
fwual_result_t fwual_finalize_image(fwual_session_t *session,
                  fwual_image_id_t image_id);

/**
 * @brief Verifies the integrity of a finalized image
 *
 * Computes the hash algorithm specified in fwual_image_desc_t::hash_algo over
 * the complete written image - streamed directly from storage, not loaded into
 * RAM - and compares the result against fwual_image_desc_t::expected_hash.
 * Must be called for every image before fwual_commit_session().
 *
 * A partially written or corrupt image MUST NOT be activated. If this function
 * returns any error, the image must be re-prepared or the session must be
 * closed before any activation attempt.
 *
 * @param[in] session Active session handle
 * @param[in] image_id Target image identifier
 *
 * @retval FWUAL_OK if hash matches
 * @retval FWUAL_ERR_CORRUPT if the computed hash does not match expected_hash
 * @retval FWUAL_ERR_INVALID_STATE if the image was not finalized
 */
fwual_result_t fwual_verify_image(fwual_session_t *session,
                  fwual_image_id_t image_id);

/**
 * @brief Atomically commits all prepared and verified images in the session
 *
 * Stages all images in the session for activation as a single atomic
 * operation. All images MUST be finalized and verified before this call.
 * If any image has not been finalized and verified, the entire session fails
 * and FWUAL_ERR_INVALID_STATE is returned - no partial commit is performed.
 *
 * After a successful commit, call fwual_activate() to set bootloader flags,
 * then initiate a reboot.
 *
 * @param[in] session Active session handle
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_INVALID_STATE if one or more images are not
 *   finalized and verified
 */
fwual_result_t fwual_commit_session(fwual_session_t *session);

/**
 * @brief Activates committed images by setting bootloader flags
 *
 * Instructs the bootloader (MCUBoot, PSA FWU, RAUC, etc.) to boot from the
 * newly committed images on the next reset. Does NOT trigger a reboot; the
 * caller (OTA Agent) is responsible for initiating the system reboot after
 * this call returns FWUAL_OK.
 *
 * After reboot, fwual_get_state() will return FWUAL_STATE_WAITING_CONFIRM.
 * FWUAL SHALL NOT force the reboot itself.
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_INVALID_STATE if the session was not committed
 */
fwual_result_t fwual_activate(void);

/**
 * @brief Confirms that the newly activated firmware is running correctly
 *
 * Must be called after reboot when fwual_get_state() returns
 * FWUAL_STATE_WAITING_CONFIRM. Marks the new image as permanently active,
 * preventing automatic rollback on the next reboot. This operation is
 * device-scoped (not session-scoped) and persists across power cycles.
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_INVALID_STATE if not in FWUAL_STATE_WAITING_CONFIRM
 */
fwual_result_t fwual_confirm(void);

/**
 * @brief Rolls back to the previously installed known-good firmware
 *
 * Integrates with the platform update mechanism to restore the previous image.
 * Can be called from any state to recover from a failed or unconfirmed update.
 * After a successful rollback, the device is left in a bootable known-good
 * state and fwual_get_state() returns FWUAL_STATE_ROLLED_BACK.
 *
 * @retval FWUAL_OK upon success
 * @retval FWUAL_ERR_PLATFORM if no previous image is available or the
 *   platform rollback mechanism failed
 */
fwual_result_t fwual_rollback(void);

/**
 * @brief Returns the current device-level update state
 *
 * Reads the persisted update state from NVM. This state survives reboots and
 * power loss. The OTA Agent SHOULD call this on startup to detect interrupted
 * sessions (FWUAL_STATE_WRITING, FWUAL_STATE_COMMITTED) or pending
 * confirmations (FWUAL_STATE_WAITING_CONFIRM).
 *
 * @retval Current fwual_state_t value. If the backend cannot be read,
 *   FWUAL_STATE_FAILED is returned
 */
fwual_state_t fwual_get_state(void);

/**
 * @brief Lists currently installed images and their versions
 *
 * Populates list with up to *in_out_count installed image descriptors. If the
 * number of installed images exceeds *in_out_count, the list is truncated and
 * *in_out_count is updated to the total number of installed images so the
 * caller can retry with a sufficiently large buffer. FWUAL_OK is returned in
 * both the full and truncated cases.
 *
 * @param[out] list Array to populate. Must not be NULL
 * @param[in,out] in_out_count On input: capacity of list (number of elements).
 *   On output: number of elements written, or required size if truncated
 *
 * @retval FWUAL_OK upon success (including truncated case)
 * @retval FWUAL_ERR_INVALID_PARAM if list or in_out_count is NULL
 */
fwual_result_t fwual_list_installed(fwual_installed_image_t *list,
                    size_t *in_out_count);

/**
 * @brief Queries whether an image is fully written and verified in the current session
 *
 * Returns true if the specified image has been finalized and its integrity
 * verified (i.e. fwual_finalize_image() and fwual_verify_image() have both
 * returned FWUAL_OK) within the current session. Returns false in all other
 * cases, including if session is NULL or image_id was not prepared.
 *
 * @param[in] session Active session handle
 * @param[in] image_id Target image identifier
 *
 * @retval true if the image is staged (finalized and verified)
 * @retval false otherwise
 */
bool fwual_is_image_staged(fwual_session_t *session, fwual_image_id_t image_id);

#endif /* __FWUAL_H__ */