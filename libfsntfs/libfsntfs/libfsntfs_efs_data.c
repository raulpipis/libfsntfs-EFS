#include <common.h>
#include <memory.h>
#include <types.h>

#include "libfsntfs_efs_data.h"
#include "libfsntfs_file_entry.h"
#include "libfsntfs_libfdata.h"
#include "libfsntfs_attribute.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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
    libcerror_error_t **error )
{
    static char *function                                   = "libfsntfs_efs_data_get_data_at_offset";
    uint8_t *buffer_location                                = NULL;
    size64_t data_in_buffer                                 = 0;
    off64_t data_run_offset                                 = 0;
    int number_of_data_runs                                 = 0;
    int i                                                   = 0;
    libfsntfs_internal_file_entry_t *internal_file_entry    = NULL;

    if (file_entry == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid file_entry.",
		 function );

		return( -1 );
    }

    if (buffer == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
    }

    internal_file_entry = (libfsntfs_internal_file_entry_t *)file_entry;

    if (internal_file_entry->file_io_handle == NULL)
    {
        libcerror_error_set(
        error,
        LIBCERROR_ERROR_DOMAIN_RUNTIME,
        LIBCERROR_RUNTIME_ERROR_VALUE_MISSING ,
        "%s: file_io_handle to volume not found in file_entry.",
        function );
    }

    if (libfsntfs_attribute_get_number_of_data_runs(
        internal_file_entry->data_attribute,
        &number_of_data_runs,
        error ) != 1 )
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

    data_run_offset = offset;
    buffer_location = buffer;
    data_in_buffer = 0;

    for(i = 0; i < number_of_data_runs && data_in_buffer < size; i++)
    {
        libfsntfs_data_run_t *data_run = NULL;
        size64_t data_to_read = 0;

        if (libfsntfs_attribute_get_data_run_by_index(
            internal_file_entry->data_attribute,
            i,
            &data_run,
            error) != 1)
        {
            return ( -1 );
        }

        /* If data is in the next data_run, adjust offset and continue
         */
        if (data_run_offset >= data_run->size)
        {
            data_run_offset -= data_run->size;
            continue;
        }

        if (libbfio_handle_seek_offset(
                internal_file_entry->file_io_handle,
                data_run->start_offset + data_run_offset,
                SEEK_SET,
                error) == -1)
        {
            libcerror_error_set(
            error,
            LIBCERROR_ERROR_DOMAIN_IO,
            LIBCERROR_IO_ERROR_SEEK_FAILED,
            "%s: seek in volume failed.",
            function );

            return ( -1 );
        }

        /* If all data is in this data run
         */
        if (size - data_in_buffer + data_run_offset <= data_run->size)
        {
            data_to_read = size - data_in_buffer;
        }
        else
        {
            data_to_read = data_run->size - data_run_offset;
        }

        /* It might happen to not be able to read all data at once
         */
        while (data_to_read > 0)
        {
            size64_t read_data = 0;
            read_data = libbfio_handle_read_buffer(
                        internal_file_entry->file_io_handle,
                        buffer_location,
                        data_to_read,
                        error);

            if (read_data == -1)
            {
                libcerror_error_set(
                error,
                LIBCERROR_ERROR_DOMAIN_IO,
                LIBCERROR_IO_ERROR_READ_FAILED,
                "%s: read from volume failed.",
                function );

                return ( -1 );
            }

            /* Seek the already read bytes
             */
            if (libbfio_handle_seek_offset(
                internal_file_entry->file_io_handle,
                read_data,
                SEEK_CUR,
                error) == -1)
            {
                libcerror_error_set(
                error,
                LIBCERROR_ERROR_DOMAIN_IO,
                LIBCERROR_IO_ERROR_SEEK_FAILED,
                "%s: seek in volume failed.",
                function );

                return ( -1 );
            }
            data_to_read -= read_data;
            data_in_buffer += read_data;
            buffer_location += read_data;
        }
        /*In the next data run data is read from the start
         */
        data_run_offset = 0;
    }
    return ( data_in_buffer );
}

/* EFS-NTFS pads the actual data with zeros up to
 * the nearest sector size (512 bytes) multiple.
 * This function just does that rounding
 * Returns 1 on success, -1 on error
 */
int libfsntfs_efs_data_get_encrypted_data_size(
    libfsntfs_file_entry_t *file_entry,
    size64_t *encrypted_data_size,
    libcerror_error_t **error )
{
    static char *function                                   = "libfsntfs_efs_data_get_encrypted_data_size";
    libfsntfs_internal_file_entry_t *internal_file_entry    = NULL;

    if (file_entry == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid file_entry.",
		 function );

		return( -1 );
    }

    if (encrypted_data_size == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid encrypted_data_size.",
		 function );

		return( -1 );
    }

    internal_file_entry = (libfsntfs_internal_file_entry_t *)file_entry;

    if (internal_file_entry->data_size % 512 > 0)
    {
        *encrypted_data_size = 
            (internal_file_entry->data_size / 512 + 1) * 512;
    }
    else
    {
        *encrypted_data_size = internal_file_entry->data_size;
    }
    return ( 1 );
}

/* Reads size raw encrypted bytes from the file starting at offset 
 * Returns number of bytes read on success
 * or -1 on error
 */
int libfsntfs_efs_data_get_encrypted_data_at_offset(
    libfsntfs_file_entry_t *file_entry,
    uint8_t *buffer,
    size64_t size,
    off64_t offset,
    libcerror_error_t **error )
{
    static char *function                                   = "libfsntfs_efs_data_get_encrypted_data_at_offset";
    size64_t encrypted_data_size                            = 0;
    if (file_entry == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid file_entry.",
		 function );

		return( -1 );
    }

    if (buffer == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
    }

    libfsntfs_efs_data_get_encrypted_data_size(
        file_entry, &encrypted_data_size, error );

    if (offset >= encrypted_data_size)
    {
        return ( 0 );
    }

    if (offset + size > encrypted_data_size)
    {
        size = encrypted_data_size - offset;
    }

    return libfsntfs_efs_data_get_data_at_offset(
        file_entry,
        buffer,
        size,
        offset,
        error );
}

/* Retrieves the file size
 * Returns 1 on success, -1 on error
 */
int libfsntfs_efs_data_get_decrypted_data_size(
    libfsntfs_file_entry_t *file_entry,
    size64_t *decrypted_data_size,
    libcerror_error_t **error )
{
    static char *function                                   = "libfsntfs_efs_data_get_decrypted_data_size";
    libfsntfs_internal_file_entry_t *internal_file_entry    = NULL;

    if (file_entry == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid file_entry.",
		 function );

		return( -1 );
    }

    if (decrypted_data_size == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid encrypted_data_size.",
		 function );

		return( -1 );
    }

    internal_file_entry = (libfsntfs_internal_file_entry_t *)file_entry;

    *decrypted_data_size = internal_file_entry->data_size;
    return ( 1 );
}

/* Generates the IV for the sector that has to be decrypted
 */
static void generate_AES_IV(uint8_t *AES_IV, uint64_t sector)
{
    uint64_t first_increment = 0x615816657be91613;
    uint64_t second_increment = 0x121989adbe449189;
    const uint8_t start_IV[16] =
        {0x12, 0x13, 0x16, 0xe9, 0x7b, 0x65, 0x16, 0x58, 0x61, 0x89, 0x91, 0x44, 0xbe, 0xad, 0x89, 0x19}; 
    int i;
       
    first_increment += sector * 2;
    second_increment += sector * 2;

    memory_copy(AES_IV, start_IV, 16);

    for(i = 0; i < sizeof(uint64_t); i++) {
        AES_IV[i + 1] = first_increment & (uint64_t)0xFF;
        AES_IV[(i + 9) & 0xF] = second_increment & (uint64_t)0xFF;

        first_increment = first_increment >> 8;
        second_increment = second_increment >> 8;
    }
}

/* Reads size decrypted bytes from the file starting at offset
 * key represents the symmetrical encryption/decryption key
 * key_size selects the algorithm used to decrypt the file
 * 32 - AES-256
 * 21 - 3DES (currently not supported)
 * 23 - DES-X (currently not supported)
 * Returns number of bytes read on success, or -1 on error
 */
int libfsntfs_efs_data_get_decrypted_data_at_offset(
    libfsntfs_file_entry_t *file_entry,
    uint8_t *buffer,
    size64_t size,
    off64_t offset,
    uint8_t *key,
    uint32_t key_size,
    libcerror_error_t **error )
{
    static char *function                                   = "libfsntfs_efs_data_get_decrypted_data_at_offset";
    size64_t decrypted_file_size                            = 0;
    size64_t total_bytes_read                               = 0;
    int retvalue                                            = 1;
    EVP_CIPHER_CTX *ctx                                     = NULL;
    uint8_t start_IV[16];
    uint8_t read_buffer[512];
    uint8_t decryption_buffer[512];

    if (file_entry == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid file_entry.",
		 function );

		return( -1 );
    }

    if (buffer == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid buffer.",
		 function );

		return( -1 );
    }

    if (key == NULL)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid key.",
		 function );

		return( -1 );
    }

    libfsntfs_efs_data_get_decrypted_data_size(
        file_entry, &decrypted_file_size, error );

    if (offset >= decrypted_file_size)
    {
        return ( 0 );
    }

    if (offset + size > decrypted_file_size)
    {
        size = decrypted_file_size - offset;
    }

    if (key_size == 32)
    {
        off64_t current_offset = offset;
        off64_t first_offset_after = offset + size;

        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);

        if (!(ctx = EVP_CIPHER_CTX_new()))
        {
            libcerror_error_set(
                error,
                LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
                LIBCERROR_ENCRYPTION_ERROR_DECRYPT_FAILED,
                "%s: decryption context initialization failure.",
                function );

                retvalue = -1;
                goto clean_openssl;
        }
        while (total_bytes_read < size)
        {
            const uint8_t *IV = NULL;
            uint8_t *ciphertext = NULL;
            size64_t read_size = 0;
            off64_t read_start_offset = 0;
            off64_t next_sector_offset = 0;
            off64_t frontal_padding_bytes = 0;
            off64_t rear_padding_bytes = 0;
            off64_t read_stop_offset = 0;
            int len = 0;
            int ciphertext_len = 0;

            /* Round down to the nearest AES block
             */ 
            read_start_offset = (current_offset / 16) * 16;
            /* Number of padding to the nearest AES block rounded down
             */
            frontal_padding_bytes = current_offset % 16;
            /* Find the location of the next sector
             */
            next_sector_offset = (current_offset / 512 + 1) * 512;
            /* If data goes into the next sector
             */
            if (first_offset_after > next_sector_offset)
            {
                read_stop_offset = next_sector_offset;
                rear_padding_bytes = 0;
            }
            else
            {
                if (first_offset_after % 16 > 0) {
                    read_stop_offset = (first_offset_after / 16 + 1) * 16 ;
                    rear_padding_bytes = read_stop_offset - first_offset_after;                    
                }
                else
                {
                    read_stop_offset = first_offset_after;
                    rear_padding_bytes = 0;
                }
            }
            read_size = read_stop_offset - read_start_offset;
            /* If the read_start_offset is not at the start of a sector
             * another sector from the front must be read as iv
             */
            if (read_start_offset % 512 > 0)
            {
                if (libfsntfs_efs_data_get_data_at_offset(
                    file_entry,
                    read_buffer,
                    read_size + 16,
                    read_start_offset - 16,
                    error ) == -1)
                {
                    retvalue = -1;
                    goto free_context;
                }

                IV = read_buffer;
                ciphertext = read_buffer + 16;
                ciphertext_len = read_size;
            }
            else
            {
                if (libfsntfs_efs_data_get_data_at_offset(
                    file_entry,
                    read_buffer,
                    read_size,
                    read_start_offset,
                    error ) == -1)
                {
                    retvalue = -1;
                    goto free_context;
                }
                
                generate_AES_IV(start_IV, read_start_offset >> 9);
                IV = start_IV;
                ciphertext = read_buffer;
                ciphertext_len = read_size;
            }

            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, IV))
            {
                libcerror_error_set(
                error,
                LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
                LIBCERROR_ENCRYPTION_ERROR_DECRYPT_FAILED,
                "%s: decryption function initialization failure.",
                function );

                retvalue = -1;
                goto free_context;
            }
            EVP_CIPHER_CTX_set_padding(ctx, 0);
            if(1 != EVP_DecryptUpdate(ctx, decryption_buffer, &len, ciphertext, ciphertext_len))
            {
                libcerror_error_set(
                error,
                LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
                LIBCERROR_ENCRYPTION_ERROR_DECRYPT_FAILED,
                "%s: decryption failure.",
                function );

                retvalue = -1;
                goto free_context;
            }
            if(1 != EVP_DecryptFinal_ex(ctx, decryption_buffer + len, &len))
            {
                ERR_print_errors_fp(stdout);
                libcerror_error_set(
                error,
                LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
                LIBCERROR_ENCRYPTION_ERROR_DECRYPT_FAILED,
                "%s: decryption finalization failure.",
                function );

                retvalue = -1;
                goto free_context;
            }

            memory_copy(buffer + total_bytes_read, 
                        decryption_buffer + frontal_padding_bytes,
                        read_size - frontal_padding_bytes - rear_padding_bytes);
            total_bytes_read += read_size - frontal_padding_bytes - rear_padding_bytes;
            current_offset = next_sector_offset;
        }
        retvalue = total_bytes_read;
free_context:
        EVP_CIPHER_CTX_free(ctx);
clean_openssl:
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
        return retvalue;
    }
    else if (key_size == 21 || key_size == 23)
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: currently unsupported algorithm.",
		 function );

		return( -1 );
    }
    else
    {
        libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid key_size.",
		 function );

		return( -1 );
    }
    return ( -1 );
}