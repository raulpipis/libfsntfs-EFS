#include <common.h>
#include <memory.h>
#include <types.h>

#include "libfsntfs_attribute.h"
#include "libfsntfs_definitions.h"
#include "libfsntfs_efs_attribute.h"
#include "libfsntfs_libbfio.h"
#include "libfsntfs_libuna.h"

//#include <tomcrypt.h>
//extern const ltc_math_descriptor ltm_desc;
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

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
int libfsntfs_efs_attribute_initialize_data(
    libfsntfs_attribute_t *attribute,
    libfsntfs_volume_t *volume,
    libcerror_error_t **error)
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    libfsntfs_internal_volume_t *internal_volume       = NULL;
	static char *function                              = "libfsntfs_efs_attribute_initialize_data";
    int i                                              = 0;
    int number_of_data_runs                            = 0;

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( volume == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid volume.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data != NULL &&
        internal_attribute->data_size != 0 ) 
    {
        return ( 0 );
    }

    internal_volume = (libfsntfs_internal_volume_t *) volume;
    if ( !internal_volume->file_io_handle_opened_in_library )
    {
        libcerror_error_set(
        error,
        LIBCERROR_ERROR_DOMAIN_IO,
        LIBCERROR_IO_ERROR_INVALID_RESOURCE,
        "%s: volume has no opened handle to file.",
        function );

        return ( -1 );
    }

    if (libfsntfs_attribute_get_number_of_data_runs(
        attribute,
        &number_of_data_runs,
        error ) != 1)
    {
        return ( -1 );
    }

    if (number_of_data_runs <= 0)
    {
        libcerror_error_set(
        error,
        LIBCERROR_ERROR_DOMAIN_RUNTIME,
        LIBCERROR_RUNTIME_ERROR_GET_FAILED,
        "%s: no data available.",
        function );

        return ( -1 );
    }
    for (i = 0; i < number_of_data_runs; ++i)
    {
        libfsntfs_data_run_t *data_run;
        uint8_t *copy_location;

        if (libfsntfs_attribute_get_data_run_by_index(
            attribute,
            i,
            &data_run,
            error) != 1)
        {
            return ( -1 );
        }

        if (internal_attribute->data == NULL)
        {
            internal_attribute->data = memory_allocate(data_run->size * sizeof(uint8_t));
            if (internal_attribute->data == NULL)
            {
                libcerror_error_set(
                error,
                LIBCERROR_ERROR_DOMAIN_MEMORY,
                LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
                "%s: unable to create data buffer.",
                function );

                return ( -1 );
            }
            internal_attribute->data_size = data_run->size;
            copy_location = internal_attribute->data;
        }
        else
        {
            uint8_t *new_data;
            new_data = memory_reallocate(
                internal_attribute->data,
                (internal_attribute->data_size + data_run->size) * sizeof(uint8_t) );
            if (new_data == NULL)
            {
                libcerror_error_set(
                error,
                LIBCERROR_ERROR_DOMAIN_MEMORY,
                LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
                "%s: unable to realloc data buffer.",
                function );

                goto on_error;
            }
            copy_location = internal_attribute->data + internal_attribute->data_size;
            internal_attribute->data_size += data_run->size;
            internal_attribute->data = new_data;
        }
        if ( libbfio_handle_seek_offset(
            internal_volume->file_io_handle,
            data_run->start_offset,
            SEEK_SET,
            error) == -1)
        {
            libcerror_error_set(
            error,
            LIBCERROR_ERROR_DOMAIN_IO,
            LIBCERROR_IO_ERROR_SEEK_FAILED,
            "%s: unable to seek in volume.",
            function );

            goto on_error;
        }
        if ( libbfio_handle_read_buffer(
             internal_volume->file_io_handle,
             copy_location,
             data_run->size,
             error) == -1)
        {
            libcerror_error_set(
            error,
            LIBCERROR_ERROR_DOMAIN_IO,
            LIBCERROR_IO_ERROR_READ_FAILED,
            "%s: unable to read data run.",
            function );

            goto on_error;
        }
    }
    return ( 1 );

on_error:
    if (internal_attribute->data != NULL)
    {
        memory_free (internal_attribute->data);
        internal_attribute->data = NULL;
        internal_attribute->data_size = 0;
    }
    return ( -1 );
}

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
int libfsntfs_efs_attribute_free_data(
    libfsntfs_attribute_t *attribute,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    static char *function                              = "libfsntfs_efs_attribute_free_data";

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if ( internal_attribute->data == NULL ||
        internal_attribute->data_size == 0 )
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_GENERIC,
		 "%s: no data to be freed",
		 function );

		return( -1 );
    }

    memory_free(internal_attribute->data);
    internal_attribute->data = NULL;
    internal_attribute->data_size = 0;
    return ( 1 );
}

/* Retrieves a generic DF(Data Field) array header
 * Returns 1 on success, 0 if not present, -1 on error
 */
int libfsntfs_efs_attribute_get_generic_df_array(
    libfsntfs_attribute_t *attribute,
    fsntfs_efs_df_array_header_t **df_array,
    int data_field_array_selector,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
	static char *function                              = "libfsntfs_efs_attribute_get_generic_df_array";
    fsntfs_efs_attribute_header_t *efs_header          = NULL;

	if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    if (df_array == NULL)
    {
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid ddf_array.",
		 function );

		return( -1 );
	}

    if (*df_array != NULL)
    {
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid ddf_array value already set.",
		 function );

		return( -1 );
	}
    
    efs_header = 
            (fsntfs_efs_attribute_header_t *) internal_attribute->data;
    if ( data_field_array_selector == LIBFSNTFS_EFS_DDF_ARRAY )
    {
        if ( efs_header->offset_to_ddf_array == 0 )
        {
            return ( 0 );
        }
        *df_array = (fsntfs_efs_df_array_header_t *)
            (efs_header->offset_to_ddf_array + (uint8_t *)(efs_header));
        return ( 1 );
    }
    else if ( data_field_array_selector == LIBFSNTFS_EFS_DRF_ARRAY )
    {
        if ( efs_header->offset_to_drf_array == 0 )
        {
            return ( 0 );
        }
        *df_array = (fsntfs_efs_df_array_header_t *)
            (efs_header->offset_to_drf_array + (uint8_t *)(efs_header));
        return ( 1 );
    }
    libcerror_error_set(
     error,
     LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
     LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
     "%s: invalid data_field_array_selector value.",
     function );

    return( -1 );
}

/* Retrieves a DF(Data Field) from a DF array
 * Returns 1 on success, 0 if the DF array is not present
 * or -1 on error
 */
int libfsntfs_efs_attribute_get_generic_df_by_index(
    libfsntfs_attribute_t *attribute,
    uint32_t index,
    int data_field_array_selector,
    fsntfs_efs_df_header_t **df_header,
    libcerror_error_t **error)
{
	static char *function                              = "libfsntfs_efs_attribute_get_generic_df_by_index";
    fsntfs_efs_df_array_header_t *df_array             = NULL;
    int retvalue                                       = 0;
    fsntfs_efs_df_header_t *current_header             = NULL;
    int i                                              = 0;

    if (df_header == NULL)
    {
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid df_header.",
		 function );

		return( -1 );
	}

    if (*df_header != NULL)
    {
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid df_header value already set.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_array(
        attribute,
        &df_array,
        data_field_array_selector,
        error );
    if (retvalue != 1)
        return retvalue;
    
    if (index < 0 || index >= df_array->df_count)
    {
        libcerror_error_set(
        error,
        LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
        LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
        "%s: index out of bounds.",
        function );

        return( -1 );
    }

    current_header = (fsntfs_efs_df_header_t *)
        ((uint8_t *)df_array + sizeof(df_array->df_count));
    
    for(i = 0; i < index; ++i) {
        current_header = (fsntfs_efs_df_header_t *)
            ((uint8_t *)current_header + current_header->df_length);
    }
    *df_header = current_header;
    return ( 1 );
}

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
    libcerror_error_t **error )
{
    static char *function                              = "libfsntfs_efs_attribute_get_FEK_size_and_FEK_from_df";
    int retvalue                                       = 1;
    uint8_t *encrypted_fek                             = NULL;
    RSA *rsa_key                                       = NULL;
    int rsa_modulus_size                               = 0;
    BIO *keybio                                        = NULL;
    int decrypted_fek_data_size                        = 0;
    int i                                              = 0;
    /* 256 because maximal RSA key modulus used is 2048 bits
     */
    uint8_t inverted_encrypted_fek[256];
    uint8_t decrypted_fek_data[256];

    if ( fek_buffer_size == NULL )
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid fek_buffer_size.",
		 function );

		return( -1 );
    }

    if ( retrieve_fek && fek_buffer == NULL )
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid fek_buffer.",
		 function );

		return( -1 );
    }

    if ( retrieve_fek && *fek_buffer != NULL )
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid fek_buffer value already set.",
		 function );

		return( -1 );
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    keybio = BIO_new_mem_buf(rsa_pem_key, rsa_pem_key_size);
    if (keybio == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: OPENSSL error, unable to create BIO",
		 function );

        retvalue = -1;
        goto clean_openssl;
    }

    rsa_key = PEM_read_bio_RSAPrivateKey(keybio, &rsa_key, NULL, NULL);

    if(rsa_key == NULL){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid PEM format RSA private key",
		 function );

        retvalue = -1;
		goto clean_bio;
    }

    rsa_modulus_size = RSA_size(rsa_key);

    if (rsa_modulus_size != df_header->fek_size)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid RSA modulus size.",
		 function );

		retvalue = -1;
        goto clean_rsa;
    }

    encrypted_fek = (uint8_t *)df_header + df_header->fek_offset;

    for ( i = 0; i < rsa_modulus_size; ++i )
    {
        inverted_encrypted_fek[i] = encrypted_fek[rsa_modulus_size - 1 - i];
    }

    decrypted_fek_data_size = 
        RSA_private_decrypt(df_header->fek_size, inverted_encrypted_fek,
                            decrypted_fek_data, rsa_key, RSA_PKCS1_PADDING);

    if (decrypted_fek_data_size == -1)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
		 LIBCERROR_ENCRYPTION_ERROR_DECRYPT_FAILED,
		 "%s: RSA decryption failed, possible padding error.",
		 function );

		retvalue = -1;
        goto clean_rsa;
    }

    /* First 16 bytes are a header
     */
    *fek_buffer_size = decrypted_fek_data_size - 16;

    if (retrieve_fek)
    {
        *fek_buffer = memory_allocate(*fek_buffer_size * sizeof(uint8_t));
        if (fek_buffer == NULL)
        {
            libcerror_error_set(
            error,
            LIBCERROR_ERROR_DOMAIN_MEMORY,
            LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
            "%s: unable to create data buffer.",
            function );

            retvalue = -1;
            goto clean_rsa;
        }
        memory_copy(*fek_buffer, decrypted_fek_data + 16, *fek_buffer_size);
    }

clean_rsa:
    RSA_free(rsa_key);
clean_bio:
    BIO_free(keybio);
clean_openssl:
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return retvalue;
}

/* Retrieves the credential header from a data field
 * Returns 1 on success, -1 on error
 */
int libfsntfs_efs_attribute_get_credential_header_from_df(
    fsntfs_efs_df_header_t *df,
    fsntfs_efs_credential_header_t **credential_header,
    libcerror_error_t **error )
{
    static char *function                              = "libfsntfs_efs_attribute_get_credential_header_from_df";

    if( df == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid df.",
		 function );

		return( -1 );
	}

    if( credential_header == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    if (*credential_header != NULL)
    {
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid credential_header value already set.",
		 function );

		return( -1 );
	}

    *credential_header = (fsntfs_efs_credential_header_t *)
                         ((uint8_t *)df + df->credential_header_offset);
    return ( 1 );
}

/* Retrieves the certificate thumbprint header from a credential header
 * if the credential header has a certificate thumbprint
 * Returns 1 on success, 0 if the credential header does not have a certificate thumprint
 * or -1 on error
 */
int libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
    fsntfs_efs_credential_header_t *credential_header,
    fsntfs_efs_certificate_thumbprint_header_t **certificate_thumbprint_header,
    libcerror_error_t **error )
{
    static char *function                              = "libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header";

    if( credential_header == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid credential header.",
		 function );

		return( -1 );
	}

    if( certificate_thumbprint_header == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid certificate thumbprint header.",
		 function );

		return( -1 );
	}

    if (*certificate_thumbprint_header != NULL)
    {
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid certificate thumbprint header value already set.",
		 function );

		return( -1 );
	}

    if (credential_header->type != 3) {
        return 0;
    }

    *certificate_thumbprint_header = (fsntfs_efs_certificate_thumbprint_header_t *)
                    ((uint8_t *)credential_header + 
                    credential_header->credential.certificate_thumbprint.cert_thumbprint_header_offset);

    return ( 1 );
}

/* Retrieves the DDF(Data Decryption Field) array size
 * Returns 1 on success, 0 if not present, -1 on error
 */
int libfsntfs_efs_attribute_get_ddf_array_size(
    libfsntfs_attribute_t *attribute,
    uint32_t *ddf_array_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
	static char *function                              = "libfsntfs_efs_attribute_get_ddf_array_size";
    fsntfs_efs_df_array_header_t *ddf_array            = NULL;
    int retvalue                                       = 0;

	if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    if (ddf_array_size == NULL)
    {
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid ddf_array_size.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_array(
        attribute,
        &ddf_array,
        LIBFSNTFS_EFS_DDF_ARRAY,
        error);
    if (retvalue == -1)
        return ( -1 );
    if (retvalue == 0) {
        *ddf_array_size = 0;
        return ( 0 );
    }
    *ddf_array_size = ddf_array->df_count;
    return ( 1 );
}

/* Retrieves the key size from the DDF entry at index
 * Returns 1 on success, 0 if the DDF has no entries,
 * -1 on error
 */
int libfsntfs_efs_attribute_get_ddf_encrypted_FEK_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint32_t *fek_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
	static char *function                              = "libfsntfs_efs_attribute_get_ddf_encrypted_FEK_size_by_index";
    fsntfs_efs_df_header_t *df_header                  = NULL; 
    int retvalue                                       = 0;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    if (fek_size == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid key_size",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    *fek_size = df_header->fek_size;
    return ( 1 );
}

/* Retrieves the key from the DDF entry at index
 * Returns 1 on success, 0 if the DDF has no entries,
 * -1 on error
 */
int libfsntfs_efs_attribute_get_ddf_encrypted_FEK_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *fek_buffer,
    uint32_t fek_buffer_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
	static char *function                              = "libfsntfs_efs_attribute_get_ddf_encrypted_key_size_by_index";
    fsntfs_efs_df_header_t *df_header                  = NULL; 
    int retvalue                                       = 0;
    uint8_t *encrypted_key                             = NULL;  

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    if (fek_buffer == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid key_buffer",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if ( fek_buffer_size < df_header->fek_size )
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: key_buffer too small to fit the encrypted key",
		 function );

		return( -1 );
    }

    encrypted_key = (uint8_t *)df_header + df_header->fek_offset;
    memory_copy(fek_buffer, encrypted_key, df_header->fek_size);
    return ( 1 );
}

/* Retrieves the size of the FEK
 * A size of 32 means the encryption algorithm is AES-256,
 * a size of 21 means the algorithm is 3DES and
 * a size of 23 means the algorithm is DES-X
 * Returns 1 on success, 0 if DDF not present, -1 on error
 */
int libfsntfs_efs_attribute_get_ddf_decrypted_FEK_size_PEM_RSA_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *rsa_pem_key,
    uint32_t rsa_pem_key_size,
    uint32_t *fek_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
	static char *function                              = "libfsntfs_efs_attribute_get_ddf_decrypted_FEK_PEM_RSA_by_index";
    fsntfs_efs_df_header_t *df_header                  = NULL;
    int retvalue                                       = 0;

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    if (rsa_pem_key == NULL || rsa_pem_key_size == 0)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid rsa_pem_key.",
		 function );

		return( -1 );
    }
    
    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    return libfsntfs_efs_attribute_get_FEK_size_and_FEK_from_df(
        attribute, df_header, rsa_pem_key, rsa_pem_key_size, 
        fek_size, NULL, 0, error);
}

/* Retrieves the decrypted FEK from the DDF entry at index, 
 * using a PEM encoded RSA private key for decryption
 * returns 1 on success, 0 if DDF not present, -1 on error
 */
int libfsntfs_efs_attribute_get_ddf_decrypted_FEK_PEM_RSA_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *rsa_pem_key,
    uint32_t rsa_pem_key_size,
    uint8_t *fek_buffer,
    uint32_t fek_buffer_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
	static char *function                              = "libfsntfs_efs_attribute_get_ddf_decrypted_FEK_pem_rsa_by_index";
    fsntfs_efs_df_header_t *df_header                  = NULL; 
    int retvalue                                       = 0;
    uint8_t *decrypted_key                             = NULL;
    uint32_t fek_size                                  = 0;

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}
    
    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    if (fek_buffer == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid key_buffer",
		 function );

		return( -1 );
    }

    if ( fek_buffer == NULL || fek_buffer_size == 0 )
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid fek buffer",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (libfsntfs_efs_attribute_get_FEK_size_and_FEK_from_df(
        attribute, df_header, rsa_pem_key, rsa_pem_key_size, 
        &fek_size, &decrypted_key, 1, error) == -1 )
    {
        return retvalue;
    }

    if (fek_buffer_size < fek_size)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: fek buffer too small to fit the key",
		 function );

		return( -1 );
    }

    memory_copy(fek_buffer, decrypted_key, fek_size);
    memory_free(decrypted_key);

    return ( 1 );
}

/* Retrieves the user's SID size from the credential header
 * Returns 1 on success, 0 if DDF not present,
 * 2 if user SID not present, or -1 on error
 */
int libfsntfs_efs_attribute_get_ddf_user_sid_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *user_sid_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_user_sid_size_by_index";
    int retvalue                                       = 1;
    uint8_t *user_sid_location                        = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->sid_offset == 0)
    {
        return ( 2 );
    }

    user_sid_location = 
                    (uint8_t *)credential_header + credential_header->sid_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
	     user_sid_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     user_sid_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the user's SID from the credential header
 * Returns 1 on success, 0 if DDF not present,
 * 2 if user SID not present, or -1 on error
 */
int libfsntfs_efs_attribute_get_ddf_user_sid_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *user_sid,
    size_t user_sid_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_user_sid_by_index";
    int retvalue                                       = 1;
    uint8_t *user_sid_location                        = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->sid_offset == 0)
    {
        return ( 2 );
    }

    user_sid_location = 
                    (uint8_t *)credential_header + credential_header->sid_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         user_sid,
         user_sid_size,
	     user_sid_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the type of the credential header in the df at index 
 * in the DDF array
 * Returns 1 if the credential header is CryptoAPI container
 * 3 if the credential header is certificate thumbprint,
 * 0 if DDF not present, or -1 on error
 */
int libfsntfs_efs_attribute_get_ddf_credential_header_type_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_credential_header_type";
    int retvalue                                       = 1;
    int type                                           = 0;  

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    type = credential_header->type;
    if (type != 1 && type != 3) {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
		 "%s: invalid type of certificate thumbprint.",
		 function );

		return( -1 );
    }

    return type;
}

/* Retrieves the size of the cryptoapi container name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * name does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_cryptoapi_container_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *container_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_cryptoapi_container_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *container_name_location                   = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
		 function );

		return( -1 );
    }

    if (credential_header->credential.cryptoapi_container.container_name_offset == 0)
    {
        return ( 2 );
    }

    container_name_location = 
                    (uint8_t *)credential_header + 
                    credential_header->credential.cryptoapi_container.container_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
	     container_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     container_name_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the cryptoapi container name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * name does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_cryptoapi_container_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *container_name,
    size_t container_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_cryptoapi_container_name_by_index";
    int retvalue                                       = 1;
    uint8_t *container_name_location                   = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
		 function );

		return( -1 );
    }

    if (credential_header->credential.cryptoapi_container.container_name_offset == 0)
    {
        return ( 2 );
    }

    container_name_location = 
                    (uint8_t *)credential_header + 
                    credential_header->credential.cryptoapi_container.container_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         container_name,
         container_name_size,
	     container_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the size of the cryptoapi provider name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_cryptoapi_provider_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *provider_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_cryptoapi_provider_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *provider_name_location                    = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
		 function );

		return( -1 );
    }

    if (credential_header->credential.cryptoapi_container.provider_name_offset == 0)
    {
        return ( 2 );
    }

    provider_name_location = 
                    (uint8_t *)credential_header + 
                    credential_header->credential.cryptoapi_container.provider_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
	     provider_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     provider_name_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the cryptoapi provider name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_cryptoapi_provider_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *provider_name,
    size_t provider_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_cryptoapi_provider_name_by_index";
    int retvalue                                       = 1;
    uint8_t *provider_name_location                    = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
		 function );

		return( -1 );
    }

    if (credential_header->credential.cryptoapi_container.provider_name_offset == 0)
    {
        return ( 2 );
    }

    provider_name_location = 
                    (uint8_t *)credential_header + 
                    credential_header->credential.cryptoapi_container.provider_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         provider_name,
         provider_name_size,
	     provider_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the size of the public key blob 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, -1 on error, 
 * including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_cryptoapi_public_key_blob_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *public_key_blob_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_cryptoapi_public_key_blob_size_by_index";
    int retvalue                                       = 1;  

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
		 function );

		return( -1 );
    }

    *public_key_blob_size = 
        credential_header->credential.cryptoapi_container.public_key_blob_size;

    return ( 1 );
}

/* Retrieves the public key blob from a CryptoAPI container 
 * credential header type from the df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, -1 on error, 
 * including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_cryptoapi_public_key_blob_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *public_key_blob,
    size_t public_key_blob_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_cryptoapi_public_key_blob_by_index";
    int retvalue                                       = 1;
    uint8_t *public_key_blob_location                  = NULL;

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
		 function );

		return( -1 );
    }

    if (public_key_blob_size < 
        credential_header->credential.cryptoapi_container.public_key_blob_size)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: buffer too small to fit public key blob",
		 function );

		return( -1 );
    }

    public_key_blob_location = (uint8_t *)credential_header + 
                            credential_header->credential.cryptoapi_container.public_key_blob_offset;

    memory_copy(public_key_blob, 
                public_key_blob_location,
                credential_header->credential.cryptoapi_container.public_key_blob_size);

    return ( 1 );
}

/* Retrieves the size of the certificate thumbprint 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, -1 on error, 
 * including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_thumbprint_certificate_thumbprint_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *certificate_thumbprint_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_thumbprint_certificate_thumbprint_size_by_index";
    int retvalue                                       = 1;  

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    *certificate_thumbprint_size = thumbprint_header->thumbprint_size;

    return ( 1 );
}

/* Retrieves the certificate thumbprint 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, -1 on error, 
 * including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_thumbprint_certificate_thumbprint_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *certificate_thumbprint,
    size_t certificate_thumbprint_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    uint8_t *certificate_thumbprint_location           = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_thumbprint_certificate_thumbprint_by_index";
    int retvalue                                       = 1;  

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    if (certificate_thumbprint == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid certificate_thumbprint.",
		 function );

		return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if(certificate_thumbprint_size < thumbprint_header->thumbprint_size)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: buffer too small to fit certificate thumbprint",
		 function );

		return( -1 );
    }

    certificate_thumbprint_location = (uint8_t *)thumbprint_header + 
                                    thumbprint_header->thumbprint_offset;

    memory_copy(certificate_thumbprint, 
                certificate_thumbprint_location, 
                thumbprint_header->thumbprint_size);

    return ( 1 );
}

/* Retrieves the size of the cryptoapi provider name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi
 * provider does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_thumbprint_provider_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *provider_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_thumbprint_provider_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *provider_name_location                    = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    if (provider_name_size == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid provider name size.",
		 function );

		return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->provider_name_offset == 0)
    {
        return ( 2 );
    }

    provider_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->provider_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
	     provider_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     provider_name_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the cryptoapi provider name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi
 * provider does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_thumbprint_provider_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *provider_name,
    size_t provider_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_thumbprint_provider_name_by_index";
    int retvalue                                       = 1;
    uint8_t *provider_name_location                    = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    if (provider_name == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid provider name.",
		 function );

		return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->provider_name_offset == 0)
    {
        return ( 2 );
    }

    provider_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->provider_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         provider_name,
         provider_name_size,
	     provider_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the size of the cryptoapi container name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi
 * container does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_thumbprint_container_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *container_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_thumbprint_container_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *container_name_location                    = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    if (container_name_size == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid container name size.",
		 function );

		return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->container_name_offset == 0)
    {
        return ( 2 );
    }

    container_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->container_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
	     container_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     container_name_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the cryptoapi container name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if cryptoapi
 * container does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_thumbprint_container_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *container_name,
    size_t container_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_thumbprint_container_name_by_index";
    int retvalue                                       = 1;
    uint8_t *container_name_location                    = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    if (container_name == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid container name.",
		 function );

		return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->container_name_offset == 0)
    {
        return ( 2 );
    }

    container_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->container_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         container_name,
         container_name_size,
	     container_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the size of the user name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if
 * user name does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_thumbprint_user_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *user_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_thumbprint_user_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *user_name_location                    = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    if (user_name_size == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid user name size.",
		 function );

		return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->user_name_offset == 0)
    {
        return ( 2 );
    }

    user_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->user_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
	     user_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     user_name_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}

/* Retrieves the user name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DDF
 * Returns 1 on success, 0 if DDF not present, 2 if 
 * user name does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_ddf_thumbprint_user_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *user_name,
    size_t user_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_ddf_thumbprint_user_name_by_index";
    int retvalue                                       = 1;
    uint8_t *user_name_location                    = NULL;   

    if( attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid attribute.",
		 function );

		return( -1 );
	}

    if (user_name == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid user name.",
		 function );

		return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported attribute type.",
		 function );

		return( -1 );
	}

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: no data in attribute, try to initialize.",
		 function );

		return( -1 );
	}

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DDF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
		 function );

		return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->user_name_offset == 0)
    {
        return ( 2 );
    }

    user_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->user_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         user_name,
         user_name_size,
	     user_name_location,
	     LIBFSNTFS_EFS_MAX_STRING_SIZE,
	     LIBUNA_ENDIAN_LITTLE,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve UTF-16 string size.",
		 function );

		return( -1 );
	}

    return ( 1 );
}


/* Retrieves the DRF(Data Decryption Field) array size
 * Returns 1 on success, 0 if not present, -1 on error
 */
int libfsntfs_efs_attribute_get_drf_array_size(
    libfsntfs_attribute_t *attribute,
    uint32_t *drf_array_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_array_size";
    fsntfs_efs_df_array_header_t *drf_array            = NULL;
    int retvalue                                       = 0;

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    if (drf_array_size == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid drf_array_size.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_array(
        attribute,
        &drf_array,
        LIBFSNTFS_EFS_DRF_ARRAY,
        error);
    if (retvalue == -1)
        return ( -1 );
    if (retvalue == 0) {
        *drf_array_size = 0;
        return ( 0 );
    }
    *drf_array_size = drf_array->df_count;
    return ( 1 );
}

/* Retrieves the key size from the DRF entry at index
 * Returns 1 on success, 0 if the DRF has no entries,
 * -1 on error
 */
int libfsntfs_efs_attribute_get_drf_encrypted_FEK_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint32_t *fek_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_encrypted_FEK_size_by_index";
    fsntfs_efs_df_header_t *df_header                  = NULL; 
    int retvalue                                       = 0;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    if (fek_size == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid key_size",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    *fek_size = df_header->fek_size;
    return ( 1 );
}

/* Retrieves the key from the DRF entry at index
 * Returns 1 on success, 0 if the DRF has no entries,
 * -1 on error
 */
int libfsntfs_efs_attribute_get_drf_encrypted_FEK_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *fek_buffer,
    uint32_t fek_buffer_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_encrypted_key_size_by_index";
    fsntfs_efs_df_header_t *df_header                  = NULL; 
    int retvalue                                       = 0;
    uint8_t *encrypted_key                             = NULL;  

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    if (fek_buffer == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid key_buffer",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if ( fek_buffer_size < df_header->fek_size )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: key_buffer too small to fit the encrypted key",
         function );

        return( -1 );
    }

    encrypted_key = (uint8_t *)df_header + df_header->fek_offset;
    memory_copy(fek_buffer, encrypted_key, df_header->fek_size);
    return ( 1 );
}

/* Retrieves the size of the FEK
 * A size of 32 means the encryption algorithm is AES-256,
 * a size of 21 means the algorithm is 3DES and
 * a size of 23 means the algorithm is DES-X
 * Returns 1 on success, 0 if DRF not present, -1 on error
 */
int libfsntfs_efs_attribute_get_drf_decrypted_FEK_size_PEM_RSA_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *rsa_pem_key,
    uint32_t rsa_pem_key_size,
    uint32_t *fek_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_decrypted_FEK_PEM_RSA_by_index";
    fsntfs_efs_df_header_t *df_header                  = NULL;
    int retvalue                                       = 0;

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    if (rsa_pem_key == NULL || rsa_pem_key_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid rsa_pem_key.",
         function );

        return( -1 );
    }
    
    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    return libfsntfs_efs_attribute_get_FEK_size_and_FEK_from_df(
        attribute, df_header, rsa_pem_key, rsa_pem_key_size, 
        fek_size, NULL, 0, error);
}

/* Retrieves the decrypted FEK from the DRF entry at index, 
 * using a PEM encoded RSA private key for decryption
 * returns 1 on success, 0 if DRF not present, -1 on error
 */
int libfsntfs_efs_attribute_get_drf_decrypted_FEK_PEM_RSA_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *rsa_pem_key,
    uint32_t rsa_pem_key_size,
    uint8_t *fek_buffer,
    uint32_t fek_buffer_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_decrypted_FEK_pem_rsa_by_index";
    fsntfs_efs_df_header_t *df_header                  = NULL; 
    int retvalue                                       = 0;
    uint8_t *decrypted_key                             = NULL;
    uint32_t fek_size                                  = 0;

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }
    
    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    if (fek_buffer == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid key_buffer",
         function );

        return( -1 );
    }

    if ( fek_buffer == NULL || fek_buffer_size == 0 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid fek buffer",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (libfsntfs_efs_attribute_get_FEK_size_and_FEK_from_df(
        attribute, df_header, rsa_pem_key, rsa_pem_key_size, 
        &fek_size, &decrypted_key, 1, error) == -1 )
    {
        return retvalue;
    }

    if (fek_buffer_size < fek_size)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: fek buffer too small to fit the key",
         function );

        return( -1 );
    }

    memory_copy(fek_buffer, decrypted_key, fek_size);
    memory_free(decrypted_key);

    return ( 1 );
}

/* Retrieves the user's SID size from the credential header
 * Returns 1 on success, 0 if DRF not present,
 * 2 if user SID not present, or -1 on error
 */
int libfsntfs_efs_attribute_get_drf_user_sid_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *user_sid_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_user_sid_size_by_index";
    int retvalue                                       = 1;
    uint8_t *user_sid_location                        = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->sid_offset == 0)
    {
        return ( 2 );
    }

    user_sid_location = 
                    (uint8_t *)credential_header + credential_header->sid_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
         user_sid_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         user_sid_size,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the user's SID from the credential header
 * Returns 1 on success, 0 if DRF not present,
 * 2 if user SID not present, or -1 on error
 */
int libfsntfs_efs_attribute_get_drf_user_sid_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *user_sid,
    size_t user_sid_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_user_sid_by_index";
    int retvalue                                       = 1;
    uint8_t *user_sid_location                        = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->sid_offset == 0)
    {
        return ( 2 );
    }

    user_sid_location = 
                    (uint8_t *)credential_header + credential_header->sid_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         user_sid,
         user_sid_size,
         user_sid_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the type of the credential header in the df at index 
 * in the DRF array
 * Returns 1 if the credential header is CryptoAPI container
 * 3 if the credential header is certificate thumbprint,
 * 0 if DRF not present, or -1 on error
 */
int libfsntfs_efs_attribute_get_drf_credential_header_type_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_credential_header_type";
    int retvalue                                       = 1;
    int type                                           = 0;  

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    type = credential_header->type;
    if (type != 1 && type != 3) {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_UNSUPPORTED_VALUE,
         "%s: invalid type of certificate thumbprint.",
         function );

        return( -1 );
    }

    return type;
}

/* Retrieves the size of the cryptoapi container name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * name does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_cryptoapi_container_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *container_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_cryptoapi_container_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *container_name_location                   = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
         function );

        return( -1 );
    }

    if (credential_header->credential.cryptoapi_container.container_name_offset == 0)
    {
        return ( 2 );
    }

    container_name_location = 
                    (uint8_t *)credential_header + 
                    credential_header->credential.cryptoapi_container.container_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
         container_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         container_name_size,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the cryptoapi container name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * name does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_cryptoapi_container_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *container_name,
    size_t container_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_cryptoapi_container_name_by_index";
    int retvalue                                       = 1;
    uint8_t *container_name_location                   = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
         function );

        return( -1 );
    }

    if (credential_header->credential.cryptoapi_container.container_name_offset == 0)
    {
        return ( 2 );
    }

    container_name_location = 
                    (uint8_t *)credential_header + 
                    credential_header->credential.cryptoapi_container.container_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         container_name,
         container_name_size,
         container_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the size of the cryptoapi provider name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_cryptoapi_provider_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *provider_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_cryptoapi_provider_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *provider_name_location                    = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
         function );

        return( -1 );
    }

    if (credential_header->credential.cryptoapi_container.provider_name_offset == 0)
    {
        return ( 2 );
    }

    provider_name_location = 
                    (uint8_t *)credential_header + 
                    credential_header->credential.cryptoapi_container.provider_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
         provider_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         provider_name_size,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the cryptoapi provider name string 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi container
 * provider does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_cryptoapi_provider_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *provider_name,
    size_t provider_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_cryptoapi_provider_name_by_index";
    int retvalue                                       = 1;
    uint8_t *provider_name_location                    = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
         function );

        return( -1 );
    }

    if (credential_header->credential.cryptoapi_container.provider_name_offset == 0)
    {
        return ( 2 );
    }

    provider_name_location = 
                    (uint8_t *)credential_header + 
                    credential_header->credential.cryptoapi_container.provider_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         provider_name,
         provider_name_size,
         provider_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the size of the public key blob 
 * from a CryptoAPI container credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, -1 on error, 
 * including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_cryptoapi_public_key_blob_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *public_key_blob_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_cryptoapi_public_key_blob_size_by_index";
    int retvalue                                       = 1;  

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
         function );

        return( -1 );
    }

    *public_key_blob_size = 
        credential_header->credential.cryptoapi_container.public_key_blob_size;

    return ( 1 );
}

/* Retrieves the public key blob from a CryptoAPI container 
 * credential header type from the df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, -1 on error, 
 * including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_cryptoapi_public_key_blob_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *public_key_blob,
    size_t public_key_blob_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_cryptoapi_public_key_blob_by_index";
    int retvalue                                       = 1;
    uint8_t *public_key_blob_location                  = NULL;

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 1){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not CryptoAPI container, try Certificate thumbprint.",
         function );

        return( -1 );
    }

    if (public_key_blob_size < 
        credential_header->credential.cryptoapi_container.public_key_blob_size)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: buffer too small to fit public key blob",
         function );

        return( -1 );
    }

    public_key_blob_location = (uint8_t *)credential_header + 
                            credential_header->credential.cryptoapi_container.public_key_blob_offset;

    memory_copy(public_key_blob, 
                public_key_blob_location,
                credential_header->credential.cryptoapi_container.public_key_blob_size);

    return ( 1 );
}

/* Retrieves the size of the certificate thumbprint 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, -1 on error, 
 * including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_thumbprint_certificate_thumbprint_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *certificate_thumbprint_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_thumbprint_certificate_thumbprint_size_by_index";
    int retvalue                                       = 1;  

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    *certificate_thumbprint_size = thumbprint_header->thumbprint_size;

    return ( 1 );
}

/* Retrieves the certificate thumbprint 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, -1 on error, 
 * including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_thumbprint_certificate_thumbprint_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint8_t *certificate_thumbprint,
    size_t certificate_thumbprint_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    uint8_t *certificate_thumbprint_location           = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_thumbprint_certificate_thumbprint_by_index";
    int retvalue                                       = 1;  

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    if (certificate_thumbprint == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid certificate_thumbprint.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if(certificate_thumbprint_size < thumbprint_header->thumbprint_size)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: buffer too small to fit certificate thumbprint",
         function );

        return( -1 );
    }

    certificate_thumbprint_location = (uint8_t *)thumbprint_header + 
                                    thumbprint_header->thumbprint_offset;

    memory_copy(certificate_thumbprint, 
                certificate_thumbprint_location, 
                thumbprint_header->thumbprint_size);

    return ( 1 );
}

/* Retrieves the size of the cryptoapi provider name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi
 * provider does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_thumbprint_provider_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *provider_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_thumbprint_provider_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *provider_name_location                    = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    if (provider_name_size == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid provider name size.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->provider_name_offset == 0)
    {
        return ( 2 );
    }

    provider_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->provider_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
         provider_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         provider_name_size,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the cryptoapi provider name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi
 * provider does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_thumbprint_provider_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *provider_name,
    size_t provider_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_thumbprint_provider_name_by_index";
    int retvalue                                       = 1;
    uint8_t *provider_name_location                    = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    if (provider_name == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid provider name.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->provider_name_offset == 0)
    {
        return ( 2 );
    }

    provider_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->provider_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         provider_name,
         provider_name_size,
         provider_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the size of the cryptoapi container name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi
 * container does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_thumbprint_container_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *container_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_thumbprint_container_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *container_name_location                    = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    if (container_name_size == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid container name size.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->container_name_offset == 0)
    {
        return ( 2 );
    }

    container_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->container_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
         container_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         container_name_size,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the cryptoapi container name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if cryptoapi
 * container does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_thumbprint_container_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *container_name,
    size_t container_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_thumbprint_container_name_by_index";
    int retvalue                                       = 1;
    uint8_t *container_name_location                    = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    if (container_name == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid container name.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->container_name_offset == 0)
    {
        return ( 2 );
    }

    container_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->container_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         container_name,
         container_name_size,
         container_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the size of the user name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if
 * user name does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_thumbprint_user_name_size_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    size_t *user_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_thumbprint_user_name_size_by_index";
    int retvalue                                       = 1;
    uint8_t *user_name_location                    = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    if (user_name_size == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid user name size.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->user_name_offset == 0)
    {
        return ( 2 );
    }

    user_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->user_name_offset;
    
    if( libuna_utf16_string_size_from_utf16_stream(
         user_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         user_name_size,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}

/* Retrieves the user name string 
 * from a Certificate thumbprint credential header type from the
 * df found at index in the DRF
 * Returns 1 on success, 0 if DRF not present, 2 if 
 * user name does not exist, -1 on error, including wrong type of credential header
 */
int libfsntfs_efs_attribute_get_drf_thumbprint_user_name_by_index(
    libfsntfs_attribute_t *attribute,
    int index,
    uint16_t *user_name,
    size_t user_name_size,
    libcerror_error_t **error )
{
    libfsntfs_internal_attribute_t *internal_attribute = NULL;
    fsntfs_efs_df_header_t *df_header                  = NULL;
    fsntfs_efs_credential_header_t *credential_header  = NULL;
    fsntfs_efs_certificate_thumbprint_header_t 
                                    *thumbprint_header = NULL;
    static char *function                              = "libfsntfs_efs_attribute_get_drf_thumbprint_user_name_by_index";
    int retvalue                                       = 1;
    uint8_t *user_name_location                    = NULL;   

    if( attribute == NULL )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid attribute.",
         function );

        return( -1 );
    }

    if (user_name == NULL)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: invalid user name.",
         function );

        return( -1 );
    }

    internal_attribute = (libfsntfs_internal_attribute_t *) attribute;

    if( internal_attribute->type != LIBFSNTFS_ATTRIBUTE_TYPE_LOGGED_UTILITY_STREAM )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: unsupported attribute type.",
         function );

        return( -1 );
    }

    if( internal_attribute->data == NULL || internal_attribute->data_size == 0)
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
         "%s: no data in attribute, try to initialize.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_generic_df_by_index(
        attribute,
        index,
        LIBFSNTFS_EFS_DRF_ARRAY,
        &df_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    retvalue = libfsntfs_efs_attribute_get_credential_header_from_df(
        df_header,
        &credential_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (credential_header->type != 3){
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
         LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
         "%s: Credential is not Certificate thumbprint, try CryptoAPI container.",
         function );

        return( -1 );
    }

    retvalue = libfsntfs_efs_attribute_get_certificate_thumbprint_header_from_credential_header(
        credential_header,
        &thumbprint_header,
        error );
    if (retvalue != 1)
    {
        return retvalue;
    }

    if (thumbprint_header->user_name_offset == 0)
    {
        return ( 2 );
    }

    user_name_location = 
                    (uint8_t *)thumbprint_header + 
                    thumbprint_header->user_name_offset;
    
    if( libuna_utf16_string_copy_from_utf16_stream(
         user_name,
         user_name_size,
         user_name_location,
         LIBFSNTFS_EFS_MAX_STRING_SIZE,
         LIBUNA_ENDIAN_LITTLE,
         error ) != 1 )
    {
        libcerror_error_set(
         error,
         LIBCERROR_ERROR_DOMAIN_RUNTIME,
         LIBCERROR_RUNTIME_ERROR_GET_FAILED,
         "%s: unable to retrieve UTF-16 string size.",
         function );

        return( -1 );
    }

    return ( 1 );
}
