#if !defined( _FSNTFS_EFS_ATTRIBUTE_H )
#define _FSNTFS_EFS_ATTRIBUTE_H

#include <common.h>
#include <types.h>

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct fsntfs_efs_attribute_header fsntfs_efs_attribute_header_t;

struct fsntfs_efs_attribute_header {
	/* Length in bytes of the EFS attribute
	 */
	uint32_t length;
	/* Seems to be always 0
	 */
	uint32_t state;
	/* EFS version, seems to be always 2
	 */
	uint32_t version;
	/* Seems to be always 0
	 */
	uint32_t crypto_api_version;
	/* Possible MD5 hash of decrypted FEK
	 */
	uint8_t vector1[16];
	/* Possible MD5 hash of DDFs
	 */
	uint8_t vector2[16];
	/* Possible MD5 hash of DDRs
	 */
	uint8_t vector3[16];
	/* Offset in bytes from the start of this structure
	 * to the DDF ARRAY HEADER 
	 */
	uint32_t offset_to_ddf_array;
	/* Offset in bytes from the start of this structure
	 * to the DDR ARRAY HEADER 
	 */
	uint32_t offset_to_drf_array;
	/* Reserved
	 */
	uint32_t reserved;
};

typedef struct fsntfs_efs_df_array_header fsntfs_efs_df_array_header_t;

struct fsntfs_efs_df_array_header {
	/* The number of DDFs or DRFs (DFs) in this array. 
	 * The first element is found right after this structure.
	 * The rest of the elements can be found by adding the length
	 * of the current data field (efs_df_header->df_length) to the
	 * start of the current efs_df_header structure
	 */
	uint32_t df_count;
};

typedef struct fsntfs_efs_df_header fsntfs_efs_df_header_t;

struct fsntfs_efs_df_header {
	/* Length in bytes of this data field
	 */
	uint32_t df_length;
	/* Offset in bytes from the start of this structure
	 * to the credential header
	 */
	uint32_t credential_header_offset;
	/* Size in bytes of the RSA encrypted File Encryption Key
	 */
	uint32_t fek_size;
	/* Offset in bytes from the start of this structure
	 * to the RSA encrypted File Encryption Key
	 */
	uint32_t fek_offset;
	/* Seems to be always 0, might be padding
	 */
	uint32_t unknown;
};

typedef struct fsntfs_efs_credential_header fsntfs_efs_credential_header_t;

struct fsntfs_efs_credential_header {
	/* Length in bytes of this credential
	 */
	uint32_t credential_length;
	/* Offset in bytes from the start of this structure
	 * to the user's SID. Zero if no SID is present
	 */
	uint32_t sid_offset;
	/* The type of this credential, can take the following values:
	 * 1 - CryptoAPI container
	 * 2 - Unexpected type
	 * 3 - Certificate thumbprint
	 * other - unknown type
	 */
	uint32_t type;
	union {
		/* CryptoAPI container
		 */
		struct {
			/* Offset in bytes from the start of the
			 * efs_credential_header structure to the 
			 * name of the CryptoAPI container. 
			 * The container name is a UTF16 wide character string
			 */
			uint32_t container_name_offset;
			/* Offset in bytes from the start of the
			 * efs_credential_header structure to the 
			 * name of the crypto provider. 
			 * The provider name is a UTF16 wide character string
			 */
			uint32_t provider_name_offset;
			/* Offset in bytes from the start of the
			 * efs_credential_header structure to the 
			 * PUBLICKEYBLOB of the RSA public key associated with
			 * the RSA private key used to encrypt
			 * the File Encryption key. 
			 */
			uint32_t public_key_blob_offset;
			/* Size in bytes of the PUBLICKEYBLOB */
			uint32_t public_key_blob_size;
		} cryptoapi_container;
		/* Certificate thumbprint
		 */
		struct {
			/* Size in bytes of the certificate thumbrint header
			 */
			uint32_t cert_thumbprint_header_size;
			/* Offset in bytes from the start of the
			 * efs_credential_header structure to the 
			 * certificate thumbprint header. 
			 */
			uint32_t cert_thumbprint_header_offset;
			/* Always zero, possible padding
			 */
			uint32_t unknown1;
			/* Always zero, possible padding
			 */
			uint32_t unknown2;
		} certificate_thumbprint;
	} credential;
};

typedef struct fsntfs_efs_certificate_thumbprint_header fsntfs_efs_certificate_thumbprint_header_t;

struct fsntfs_efs_certificate_thumbprint_header {
	/* Offset in bytes from the start of this structure
	 * to the certificate's thumbprint
	 */
	uint32_t thumbprint_offset;
	/* Size in bytes of the certificate thumbprint
	 */
	uint32_t thumbprint_size;
	/* Offset in bytes from the start of this structure
	 * to the name of the CryptoAPI container, or 0 if none is present. 
	 * The container name is a UTF16 wide character string
	 */
	uint32_t container_name_offset;
	/* Offset in bytes from the start of this structure
	 * to the name of the crypto provider, or 0 if none is present. 
	 * The provider name is a UTF16 wide character string
	 */
	uint32_t provider_name_offset;
	/* Offset in bytes from the start of this structure
	 * to the name of the user that owns the file,
	 * or 0 if none is present. 
	 * The user name is a UTF16 wide character string
	 */
	uint32_t user_name_offset;
};

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _FSNTFS_EFS_ATTRIBUTE_H ) */

