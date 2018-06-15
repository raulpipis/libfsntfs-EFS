/*
 * Index value functions
 *
 * Copyright (C) 2010-2018, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <byte_stream.h>
#include <memory.h>
#include <types.h>

#include "libfsntfs_debug.h"
#include "libfsntfs_definitions.h"
#include "libfsntfs_index_value.h"
#include "libfsntfs_libcerror.h"
#include "libfsntfs_libcnotify.h"

#include "fsntfs_index.h"

/* Creates an index value
 * Make sure the value index_value is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_index_value_initialize(
     libfsntfs_index_value_t **index_value,
     libcerror_error_t **error )
{
	static char *function = "libfsntfs_index_value_initialize";

	if( index_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid index value.",
		 function );

		return( -1 );
	}
	if( *index_value != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid index value value already set.",
		 function );

		return( -1 );
	}
	*index_value = memory_allocate_structure(
	                libfsntfs_index_value_t );

	if( *index_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create index value.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *index_value,
	     0,
	     sizeof( libfsntfs_index_value_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear index value.",
		 function );

		memory_free(
		 *index_value );

		*index_value = NULL;

		return( -1 );
	}
	return( 1 );

on_error:
	if( *index_value != NULL )
	{
		memory_free(
		 *index_value );

		*index_value = NULL;
	}
	return( -1 );
}

/* Frees an index value
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_index_value_free(
     libfsntfs_index_value_t **index_value,
     libcerror_error_t **error )
{
	static char *function = "libfsntfs_index_value_free";

	if( index_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid index value.",
		 function );

		return( -1 );
	}
	if( *index_value != NULL )
	{
		if( ( *index_value )->key_data != NULL )
		{
			memory_free(
			 ( *index_value )->key_data );
		}
		if( ( *index_value )->value_data != NULL )
		{
			memory_free(
			 ( *index_value )->value_data );
		}
		memory_free(
		 *index_value );

		*index_value = NULL;
	}
	return( 1 );
}

/* Reads the index value
 * Returns the number of bytes read if successful or -1 on error
 */
size_t libfsntfs_index_value_read(
        libfsntfs_index_value_t *index_value,
        off64_t index_value_offset,
        int *index_value_entry,
        uint8_t *index_value_data,
        size_t index_value_data_size,
        size_t index_value_data_offset,
        libcerror_error_t **error )
{
	static char *function   = "libfsntfs_index_value_read";
	uint32_t remaining_size = 0;

	if( index_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid index value.",
		 function );

		return( -1 );
	}
	if( index_value_entry == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid index value entry.",
		 function );

		return( -1 );
	}
	if( index_value_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid index value data.",
		 function );

		return( -1 );
	}
	if( index_value_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: index value data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( index_value_data_offset > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: index value data offset value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( index_value_data_offset >= index_value_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: index value data offset value out of bounds.",
		 function );

		return( -1 );
	}
	if( ( index_value_data_size < sizeof( fsntfs_index_value_t ) )
	 || ( index_value_data_offset > ( index_value_data_size - sizeof( fsntfs_index_value_t ) ) ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: index value data size value too small.",
		 function );

		return( -1 );
	}
	index_value->offset = index_value_offset;

#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: index value: %03d header data:\n",
		 function,
		 *index_value_entry );
		libcnotify_print_data(
		 index_value_data,
		 sizeof( fsntfs_index_value_t ),
		 0 );
	}
#endif
	byte_stream_copy_to_uint64_little_endian(
	 ( (fsntfs_index_value_t *) &( index_value_data[ index_value_data_offset ] ) )->file_reference,
	 index_value->file_reference );

	byte_stream_copy_to_uint16_little_endian(
	 ( (fsntfs_index_value_t *) &( index_value_data[ index_value_data_offset ] ) )->size,
	 index_value->size );

	byte_stream_copy_to_uint16_little_endian(
	 ( (fsntfs_index_value_t *) &( index_value_data[ index_value_data_offset ] ) )->key_data_size,
	 index_value->key_data_size );

	byte_stream_copy_to_uint32_little_endian(
	 ( (fsntfs_index_value_t *) &( index_value_data[ index_value_data_offset ] ) )->flags,
	 index_value->flags );

#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: index value: %03d file reference\t\t: MFT entry: %" PRIu64 ", sequence: %" PRIu64 "\n",
		 function,
		 *index_value_entry,
		 index_value->file_reference & 0xffffffffffffUL,
		 index_value->file_reference >> 48 );

		libcnotify_printf(
		 "%s: index value: %03d size\t\t\t: %" PRIu16 "\n",
		 function,
		 *index_value_entry,
		 index_value->size );

		libcnotify_printf(
		 "%s: index value: %03d key data size\t\t: %" PRIu16 "\n",
		 function,
		 *index_value_entry,
		 index_value->key_data_size );

		libcnotify_printf(
		 "%s: index value: %03d flags\t\t\t: 0x%08" PRIx32 "\n",
		 function,
		 *index_value_entry,
		 index_value->flags );
		libfsntfs_debug_print_index_value_flags(
		 index_value->flags );
		libcnotify_printf(
		 "\n" );
	}
#endif
	index_value_data_offset += sizeof( fsntfs_index_value_t );

	if( ( (size_t) index_value->size < sizeof( fsntfs_index_value_t ) )
	 || ( (size_t) index_value->size > index_value_data_size ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: index value: %03d size exceeds index value data size.",
		 function,
		 *index_value_entry );

		goto on_error;
	}
	remaining_size = (size_t) index_value->size - sizeof( fsntfs_index_value_t );

	if( index_value->key_data_size > 0 )
	{
		if( (uint32_t) index_value->key_data_size > remaining_size )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: index value: %03d data size exceeds size.",
			 function,
			 *index_value_entry );

			goto on_error;
		}
		index_value->key_data = (uint8_t *) memory_allocate(
		                                     sizeof( uint8_t ) * index_value->key_data_size );

		if( index_value->key_data == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create index value: %03d key data.",
			 function,
			 *index_value_entry );

			goto on_error;
		}
		if( memory_copy(
		     index_value->key_data,
		     &( index_value_data[ index_value_data_offset ] ),
		     (size_t) index_value->key_data_size ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy index value: %03d data.",
			 function,
			 *index_value_entry );

			goto on_error;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: index value: %03d key data:\n",
			 function,
			 *index_value_entry );
			libcnotify_print_data(
			 &( index_value_data[ index_value_data_offset ] ),
			 (size_t) index_value->key_data_size,
			 0 );
		}
#endif
		index_value_data_offset += index_value->key_data_size;
		remaining_size          -= index_value->key_data_size;
	}
	if( ( index_value->flags & LIBFSNTFS_INDEX_VALUE_FLAG_HAS_SUB_NODE ) != 0 )
	{
		if( remaining_size < 8 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: index value: %03d sub node data size exceeds size.",
			 function,
			 *index_value_entry );

			goto on_error;
		}
		remaining_size -= 8;
	}
	if( remaining_size > 0 )
	{
		index_value->value_data = (uint8_t *) memory_allocate(
		                                       sizeof( uint8_t ) * remaining_size );

		if( index_value->value_data == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create index value: %03d value data.",
			 function,
			 *index_value_entry );

			goto on_error;
		}
		index_value->value_data_size = remaining_size;

		if( memory_copy(
		     index_value->value_data,
		     &( index_value_data[ index_value_data_offset ] ),
		     (size_t) index_value->value_data_size ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy index value: %03d data.",
			 function,
			 *index_value_entry );

			goto on_error;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: index value: %03d value data:\n",
			 function,
			 *index_value_entry );
			libcnotify_print_data(
			 index_value->value_data,
			 (size_t) index_value->value_data_size,
			 0 );
		}
#endif
		index_value_data_offset += remaining_size;
	}
	if( ( index_value->flags & LIBFSNTFS_INDEX_VALUE_FLAG_HAS_SUB_NODE ) != 0 )
	{
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: index value: %03d sub node VCN data:\n",
			 function,
			 *index_value_entry );
			libcnotify_print_data(
			 &( index_value_data[ index_value_data_offset ] ),
			 8,
			 0 );
		}
#endif
		byte_stream_copy_to_uint32_little_endian(
		 &( index_value_data[ index_value_data_offset ] ),
		 index_value->sub_node_vcn );

#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
			libcnotify_printf(
			 "%s: index value: %03d sub node VCN\t\t: %" PRIu64 "\n",
			 function,
			 *index_value_entry,
			 index_value->sub_node_vcn );

			libcnotify_printf(
			 "\n" );
		}
#endif
	}
	*index_value_entry += 1;

	return( (ssize_t) index_value->size );

on_error:
	if( index_value->value_data != NULL )
	{
		memory_free(
		 index_value->value_data );

		index_value->value_data = NULL;
	}
	index_value->value_data_size = 0;

	if( index_value->key_data != NULL )
	{
		memory_free(
		 index_value->key_data );

		index_value->key_data = NULL;
	}
	index_value->key_data_size = 0;

	return( -1 );
}

#if defined( HAVE_DEBUG_OUTPUT )

/* Debug prints the index value
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_index_value_print(
     libfsntfs_index_value_t *index_value,
     libcerror_error_t **error )
{
	static char *function = "libfsntfs_index_value_print";

	if( index_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid index value.",
		 function );

		return( -1 );
	}
	libcnotify_printf(
	 "%s: file reference\t\t\t\t: MFT entry: %" PRIu64 ", sequence: %" PRIu64 "\n",
	 function,
	 index_value->file_reference & 0xffffffffffffUL,
	 index_value->file_reference >> 48 );

	libcnotify_printf(
	 "%s: size\t\t\t\t\t: %" PRIu16 "\n",
	 function,
	 index_value->size );

	libcnotify_printf(
	 "%s: key data size\t\t\t\t: %" PRIu16 "\n",
	 function,
	 index_value->key_data_size );

	libcnotify_printf(
	 "%s: flags\t\t\t\t\t: 0x%08" PRIx32 "\n",
	 function,
	 index_value->flags );
	libfsntfs_debug_print_index_value_flags(
	 index_value->flags );
	libcnotify_printf(
	 "\n" );

	libcnotify_printf(
	 "%s: sub node VCN\t\t\t\t: %" PRIu64 "\n",
	 function,
	 index_value->sub_node_vcn );

/* TODO add more debug information */
	libcnotify_printf(
	 "\n" );

	return( 1 );
}

#endif /* defined( HAVE_DEBUG_OUTPUT ) */

