#if !defined( _LIBFSNTFS_EFS_ATTRIBUTE_H)
#define _LIBFSNTFS_EFS_ATTRIBUTE_H

#include <common.h>
#include <types.h>

#include "fsntfs_efs.h"
#include "libfsntfs_extern.h"
#include "libfsntfs_types.h"
#include "libfsntfs_volume.h"

#if !defined( LIBFSNTFS_EFS_DDF_ARRAY)
#define LIBFSNTFS_EFS_DDF_ARRAY 1
#endif

#if !defined( LIBFSNTFS_EFS_DRF_ARRAY)
#define LIBFSNTFS_EFS_DRF_ARRAY 2
#endif

#if !defined( LIBFSNTFS_EFS_MAX_STRING_SIZE)
#define LIBFSNTFS_EFS_MAX_STRING_SIZE 256
#endif

#if defined( __cplusplus )
extern "C" {
#endif

/* If the data pointer is not already set,
 * probably the attribute is nonresident and 
 * the data is in data_runs. This function attempts
 * to set the data pointer of the attribute from
 * these data runs. If this is the case, the corresponding
 * free function (libfsntfs_efs_attribute_free_data)
 * must be called after the attribute is no
 * longer used to free the used memory. 
 * Returns:
 *      0 if data was already present, no subsequent
 * free is required
 *      1 if data was not present and this function had to 
 * allocate memory(free is required in this case)
 *      -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_initialize_data(
    libfsntfs_attribute_t *attribute,
    libfsntfs_volume_t *volume,
    libcerror_error_t **error);

/* This function frees the data field of
 * the atrribute IF AND ONLY IF
 * libfsntfs_efs_attribute_initialize_data was called before
 * and it returned 1. If this is the case, this function MUST
 * be called ONCE in order to free the allocated memory.
 * If libfsntfs_efs_attribute_initialize_data was not called before
 * or it returned 0 or -1 this function MUST NOT be called as it
 * will have undefined behaviour
 * This function returns 1 on success, or -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_free_data(
    libfsntfs_attribute_t *attribute,
    libcerror_error_t **error );

/* Retrieves a generic DF(Data Field) array header
 * Returns 1 on success, 0 if not present, -1 on error
 */
int libfsntfs_efs_attribute_get_generic_df_array(
    libfsntfs_attribute_t *attribute,
    fsntfs_efs_df_array_header_t **df_array,
    int data_field_array_selector,
    libcerror_error_t **error );

/* Retrieves a DF(Data Field) from a DF array
 * Returns 1 on success, 0 if the DF array is not present
 * or -1 on error
 */
int libfsntfs_efs_attribute_get_generic_df_by_index(
    libfsntfs_attribute_t *attribute,
    uint32_t index,
    int data_field_array_selector,
    fsntfs_efs_df_header_t **df_header,
    libcerror_error_t **error);

/* Retrieves the FEK size and the FEK if retrieve_FEK is set
 * on a non zero value
 * Returns 1 on success or -1 on error
 * ONLY FOR INTERNAL LIBRARY USE, IF retrieve_fek IS SET,
 * THE BUFFER MUST BE FREED, ALSO IT DOES NOT CHECK attribute,
 * df_header, rsa_pem_key AND rsa_pem_key_size FOR ERRORS
 */
int libfsntfs_efs_attribute_get_FEK_size_and_FEK_from_df(
    libfsntfs_attribute_t *attribute,
    fsntfs_efs_df_header_t *df_header,
    uint8_t *rsa_pem_key,
    uint32_t rsa_pem_key_size,
    uint32_t *fek_buffer_size,
    uint8_t **fek_buffer,
    int retrieve_fek,
    libcerror_error_t **error );

/* Retrieves the credential header from a data field
 * Returns 1 on success, -1 on error
 */
int libfsntfs_efs_attribute_get_credential_header_from_df(
    fsntfs_efs_df_header_t *df,
    fsntfs_efs_credential_header_t **credential_header,
    libcerror_error_t **error );

/* Retrieves the certificate thumbprint header from a credential header
 * if the credential header has a certificate thumbprint
 * Returns 1 on success, 0 if the credential header does not have a certificate thumprint
 * or -1 on error
 */
int libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
    fsntfs_efs_credential_header_t *credential_header,
    fsntfs_efs_certificate_thumbprint_header_t **certificate_thumbprint_header,
    libcerror_error_t **error );

/* Retrieves the DDF(Data Decryption Field) array size
 * Returns 1 on success, 0 if not present, -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_array_size(
    libfsntfs_attribute_t *attribute,
    uint32_t *ddf_array_size,
    libcerror_error_t **error );

/* Retrieves the key size from the DDF entry at index
 * Returns 1 on success, 0 if the DDF has no entries,
 * -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_encrypted_FEK_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint32_t *fek_size,
    libcerror_error_t **error );

/* Retrieves the key from the DDF entry at index
 * Returns 1 on success, 0 if the DDF has no entries,
 * -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_encrypted_FEK_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *fek_buffer,
    uint32_t fek_buffer_size,
    libcerror_error_t **error );

/* Retrieves the size of the FEK
 * A size of 32 means the encryption algorithm is AES-256,
 * a size of 21 means the algorithm is 3DES and
 * a size of 23 means the algorithm is DES-X
 * Returns 1 on success, 0 if DDF not present, -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_decrypted_FEK_size_PEM_RSA_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *rsa_pem_key,
    uint32_t rsa_pem_key_size,
    uint32_t *fek_size,
    libcerror_error_t **error );

/* Retrieves the decrypted FEK from the DDF entry at index, 
 * using a PEM encoded RSA private key for decryption
 * returns 1 on success, 0 if DDF not present, -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_decrypted_FEK_PEM_RSA_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *rsa_pem_key,
    uint32_t rsa_pem_key_size,
    uint8_t *fek_buffer,
    uint32_t fek_buffer_size,
    libcerror_error_t **error );

/* Retrieves the user's SID size from the credential header
 * Returns 1 on success, 0 if DDF not present,
 * 2 if user SID not present, or -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_user_sid_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *user_sid_size,
    libcerror_error_t **error );

/* Retrieves the user's SID from the credential header
 * Returns 1 on success, 0 if DDF not present,
 * 2 if user SID not present, or -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_user_sid_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *user_sid,
    size_t user_sid_size,
    libcerror_error_t **error );

/* Retrieves the type of the credential header in the df at index 
 * in the DDF array
 * Returns 1 if the credential header is CryptoAPI container
 * 3 if the credential header is certificate thumbprint,
 * 0 if DDF not present, or -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_credential_header_type_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    libcerror_error_t **error );

/* Retrieves the size of the cryptoapi container name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * name does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_cryptoapi_container_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *container_name_size,
    libcerror_error_t **error );

/* Retrieves the cryptoapi container name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * name does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_cryptoapi_container_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *container_name,
    size_t container_name_size,
    libcerror_error_t **error );

/* Retrieves the size of the cryptoapi provider name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_cryptoapi_provider_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *provider_name_size,
    libcerror_error_t **error );

/* Retrieves the cryptoapi provider name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_cryptoapi_provider_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *provider_name,
    size_t provider_name_size,
    libcerror_error_t **error );

/* Retrieves the size of the public key blob 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, -1 on error, 
 * including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_cryptoapi_public_key_blob_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *public_key_blob_size,
    libcerror_error_t **error );

/* Retrieves the public key blob from a CryptoAPI container 
 * credential header type from the df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, -1 on error, 
 * including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_cryptoapi_public_key_blob_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *public_key_blob,
    size_t public_key_blob_size,
    libcerror_error_t **error );

/* Retrieves the size of the certificate thumbprint 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, -1 on error, 
 * including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_thumbprint_certificate_thumbprint_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *certificate_thumbprint_size,
    libcerror_error_t **error );

/* Retrieves the certificate thumbprint 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, -1 on error, 
 * including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_thumbprint_certificate_thumbprint_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *certificate_thumbprint,
    size_t certificate_thumbprint_size,
    libcerror_error_t **error );

/* Retrieves the size of the cryptoapi provider name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_thumbprint_provider_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *provider_name_size,
    libcerror_error_t **error );

/* Retrieves the cryptoapi provider name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_thumbprint_provider_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *provider_name,
    size_t provider_name_size,
    libcerror_error_t **error );

/* Retrieves the size of the cryptoapi container name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi
 * container does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_thumbprint_container_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *container_name_size,
    libcerror_error_t **error );

/* Retrieves the cryptoapi container name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi
 * container does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_thumbprint_container_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *container_name,
    size_t container_name_size,
    libcerror_error_t **error );

/* Retrieves the size of the user name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if
 * user name does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_thumbprint_user_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *user_name_size,
    libcerror_error_t **error );

/* Retrieves the user name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if 
 * user name does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_ddf_thumbprint_user_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *user_name,
    size_t user_name_size,
    libcerror_error_t **error );

/* Retrieves the DRF(Data Recovery Field) array size
 * Returns 1 on success, 0 if not present, -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_array_size(
    libfsntfs_attribute_t *attribute,
    uint32_t *drf_array_size,
    libcerror_error_t **error );

/* Retrieves the key size from the DRF entry at index
 * Returns 1 on success, 0 if the DRF has no entries,
 * -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_encrypted_FEK_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint32_t *fek_size,
    libcerror_error_t **error );

/* Retrieves the key from the DRF entry at index
 * Returns 1 on success, 0 if the DRF has no entries,
 * -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_encrypted_FEK_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *fek_buffer,
    uint32_t fek_buffer_size,
    libcerror_error_t **error );

/* Retrieves the size of the FEK
 * A size of 32 means the encryption algorithm is AES-256,
 * a size of 21 means the algorithm is 3DES and
 * a size of 23 means the algorithm is DES-X
 * Returns 1 on success, 0 if DRF not present, -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_decrypted_FEK_size_PEM_RSA_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *rsa_pem_key,
    uint32_t rsa_pem_key_size,
    uint32_t *fek_size,
    libcerror_error_t **error );

/* Retrieves the decrypted FEK from the DRF entry at index, 
 * using a PEM encoded RSA private key for decryption
 * returns 1 on success, 0 if DRF not present, -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_decrypted_FEK_PEM_RSA_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *rsa_pem_key,
    uint32_t rsa_pem_key_size,
    uint8_t *fek_buffer,
    uint32_t fek_buffer_size,
    libcerror_error_t **error );

/* Retrieves the user's SID size from the credential header
 * Returns 1 on success, 0 if DRF not present,
 * 2 if user SID not present, or -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_user_sid_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *user_sid_size,
    libcerror_error_t **error );

/* Retrieves the user's SID from the credential header
 * Returns 1 on success, 0 if DRF not present,
 * 2 if user SID not present, or -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_user_sid_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *user_sid,
    size_t user_sid_size,
    libcerror_error_t **error );

/* Retrieves the type of the credential header in the df at index 
 * in the DRF array
 * Returns 1 if the credential header is CryptoAPI container
 * 3 if the credential header is certificate thumbprint,
 * 0 if DRF not present, or -1 on error
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_credential_header_type_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    libcerror_error_t **error );

/* Retrieves the size of the cryptoapi container name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * name does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_cryptoapi_container_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *container_name_size,
    libcerror_error_t **error );

/* Retrieves the cryptoapi container name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * name does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_cryptoapi_container_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *container_name,
    size_t container_name_size,
    libcerror_error_t **error );

/* Retrieves the size of the cryptoapi provider name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_cryptoapi_provider_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *provider_name_size,
    libcerror_error_t **error );

/* Retrieves the cryptoapi provider name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_cryptoapi_provider_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *provider_name,
    size_t provider_name_size,
    libcerror_error_t **error );

/* Retrieves the size of the public key blob 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, -1 on error, 
 * including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_cryptoapi_public_key_blob_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *public_key_blob_size,
    libcerror_error_t **error );

/* Retrieves the public key blob from a CryptoAPI container 
 * credential header type from the df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, -1 on error, 
 * including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_cryptoapi_public_key_blob_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *public_key_blob,
    size_t public_key_blob_size,
    libcerror_error_t **error );

/* Retrieves the size of the certificate thumbprint 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, -1 on error, 
 * including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_thumbprint_certificate_thumbprint_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *certificate_thumbprint_size,
    libcerror_error_t **error );

/* Retrieves the certificate thumbprint 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, -1 on error, 
 * including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_thumbprint_certificate_thumbprint_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *certificate_thumbprint,
    size_t certificate_thumbprint_size,
    libcerror_error_t **error );

/* Retrieves the size of the cryptoapi provider name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_thumbprint_provider_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *provider_name_size,
    libcerror_error_t **error );

/* Retrieves the cryptoapi provider name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_thumbprint_provider_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *provider_name,
    size_t provider_name_size,
    libcerror_error_t **error );

/* Retrieves the size of the cryptoapi container name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi
 * container does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_thumbprint_container_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *container_name_size,
    libcerror_error_t **error );

/* Retrieves the cryptoapi container name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi
 * container does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_thumbprint_container_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *container_name,
    size_t container_name_size,
    libcerror_error_t **error );

/* Retrieves the size of the user name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if
 * user name does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_thumbprint_user_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *user_name_size,
    libcerror_error_t **error );

/* Retrieves the user name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if 
 * user name does not exist, -1 on error, including wrong type of credential header
 */
LIBFSNTFS_EXTERN \
int libfsntfs_efs_attribute_get_drf_thumbprint_user_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *user_name,
    size_t user_name_size,
    libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFSNTFS_EFS_ATTRIBUTE_H ) */