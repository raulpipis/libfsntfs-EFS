#if !defined( _LIBFSNTFS_EFS_DATA_H)
#define _LIBFSNTFS_EFS_DATA_H

#include <common.h>
#include <types.h>

#include "libfsntfs_extern.h"
#include "libfsntfs_types.h"
#include "libfsntfs_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

/* Reads size bytes starting from offset from the 
 * data runs of the file
 * Returns the number of bytes read on success or -1
 * on failure
 */
int libfsntfs_efs_data_get_data_at_offset(
    libfsntfs_file_entry_t *file_entry,
    uint8_t *buffer,
    size64_t size,
    off64_t offset,
    libcerror_error_t **error );

/* EFS-NTFS pads the actual data with zeros up to
 * the nearest sector size (512 bytes) multiple.
 * This function just does that rounding
 * Returns 1 on success, -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_data_get_encrypted_data_size(
    libfsntfs_file_entry_t *file_entry,
    size64_t *encrypted_data_size,
    libcerror_error_t **error );

/* Reads raw encrypted data from the file
 * Returns number of bytes read on success
 * or -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_data_get_encrypted_data_at_offset(
    libfsntfs_file_entry_t *file_entry,
    uint8_t *buffer,
    size64_t size,
    off64_t offset,
    libcerror_error_t **error );

/* Retrieves the file size
 * Returns 1 on success, -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_data_get_decrypted_data_size(
    libfsntfs_file_entry_t *file_entry,
    size64_t *decrypted_data_size,
    libcerror_error_t **error );

/* Reads size decrypted bytes from the file starting at offset
 * key represents the symmetrical encryption/decryption key
 * key_size selects the algorithm used to decrypt the file
 * 32 - AES-256
 * 21 - 3DES (currently not supported)
 * 23 - DES-X (currently not supported)
 * Returns number of bytes read on success, or -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_data_get_decrypted_data_at_offset(
    libfsntfs_file_entry_t *file_entry,
    uint8_t *buffer,
    size64_t size,
    off64_t offset,
    uint8_t *key,
    uint32_t key_size,
    libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFSNTFS_EFS_DATA_H ) */