/*
 * USN change journal functions
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

#include "libfsntfs_data_stream.h"
#include "libfsntfs_definitions.h"
#include "libfsntfs_file_entry.h"
#include "libfsntfs_types.h"
#include "libfsntfs_usn_change_journal.h"

/* Creates an USN change journal
 * Make sure the value usn_change_journal is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_usn_change_journal_initialize(
     libfsntfs_usn_change_journal_t **usn_change_journal,
     libfsntfs_io_handle_t *io_handle,
     libbfio_handle_t *file_io_handle,
     libfsntfs_directory_entry_t *directory_entry,
     libfsntfs_attribute_t *data_attribute,
     libcerror_error_t **error )
{
	libfsntfs_internal_usn_change_journal_t *internal_usn_change_journal = NULL;
	static char *function                                                = "libfsntfs_usn_change_journal_initialize";

	if( usn_change_journal == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid USN change journal.",
		 function );

		return( -1 );
	}
	if( *usn_change_journal != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid USN change journal value already set.",
		 function );

		return( -1 );
	}
	if( directory_entry == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid directory entry.",
		 function );

		return( -1 );
	}
	if( data_attribute == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid $J data attribute.",
		 function );

		return( -1 );
	}
	internal_usn_change_journal = memory_allocate_structure(
	                               libfsntfs_internal_usn_change_journal_t );

	if( internal_usn_change_journal == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create USN change journal.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_usn_change_journal,
	     0,
	     sizeof( libfsntfs_internal_usn_change_journal_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear USN change journal.",
		 function );

		memory_free(
		 internal_usn_change_journal );

		return( -1 );
	}
	if( libfsntfs_data_stream_initialize(
	     &( internal_usn_change_journal->data_stream ),
	     file_io_handle,
	     io_handle,
	     data_attribute,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_INITIALIZE_FAILED,
		 "%s: unable to create $J data stream.",
		 function );

		return( -1 );
	}
	if( libfsntfs_data_stream_get_size(
	     internal_usn_change_journal->data_stream,
	     &( internal_usn_change_journal->data_size ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve $J data stream size.",
		 function );

		goto on_error;
	}
	if( libfsntfs_data_stream_get_number_of_extents(
	     internal_usn_change_journal->data_stream,
	     &( internal_usn_change_journal->number_of_extents ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve $J data stream number of extents.",
		 function );

		goto on_error;
	}
	if( libfsntfs_data_stream_get_extent_by_index(
	     internal_usn_change_journal->data_stream,
	     internal_usn_change_journal->extent_index,
	     &( internal_usn_change_journal->extent_offset ),
	     &( internal_usn_change_journal->extent_size ),
	     &( internal_usn_change_journal->extent_flags ),
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve $J data stream extent: %d.",
		 function,
		 internal_usn_change_journal->extent_index );

		goto on_error;
	}
/* TODO what defines the journal block size? the index entry size? */
	internal_usn_change_journal->journal_block_size = 0x1000;

	internal_usn_change_journal->journal_block_data = (uint8_t *) memory_allocate(
	                                                               sizeof( uint8_t ) * internal_usn_change_journal->journal_block_size );

	if( internal_usn_change_journal->journal_block_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create journal block data.",
		 function );

		goto on_error;
	}
	internal_usn_change_journal->file_io_handle  = file_io_handle;
	internal_usn_change_journal->directory_entry = directory_entry;
	internal_usn_change_journal->data_attribute  = data_attribute;

	*usn_change_journal = (libfsntfs_usn_change_journal_t *) internal_usn_change_journal;

	return( 1 );

on_error:
	if( internal_usn_change_journal != NULL )
	{
		if( internal_usn_change_journal->data_stream != NULL )
		{
			libfsntfs_data_stream_free(
			 &( internal_usn_change_journal->data_stream ),
			 NULL );
		}
		memory_free(
		 internal_usn_change_journal );
	}
	return( -1 );
}

/* Frees an USN change journal
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_usn_change_journal_free(
     libfsntfs_usn_change_journal_t **usn_change_journal,
     libcerror_error_t **error )
{
	libfsntfs_internal_usn_change_journal_t *internal_usn_change_journal = NULL;
	static char *function                                                = "libfsntfs_usn_change_journal_free";
	int result                                                           = 1;

	if( usn_change_journal == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid USN change journal.",
		 function );

		return( -1 );
	}
	if( *usn_change_journal != NULL )
	{
		internal_usn_change_journal = (libfsntfs_internal_usn_change_journal_t *) *usn_change_journal;
		*usn_change_journal         = NULL;

		/* The file_io_handle and data_attribute references are freed elsewhere
		 */
		if( libfsntfs_directory_entry_free(
		     &( internal_usn_change_journal->directory_entry ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free directory entry.",
			 function );

			result = -1;
		}
		if( libfsntfs_data_stream_free(
		     &( internal_usn_change_journal->data_stream ),
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_FINALIZE_FAILED,
			 "%s: unable to free $J data stream.",
			 function );

			result = -1;
		}
		memory_free(
		 internal_usn_change_journal->journal_block_data );
		memory_free(
		 internal_usn_change_journal );
	}
	return( result );
}

/* Retrieves the current offset of the default data stream (nameless $DATA attribute)
 * Returns the offset if successful or -1 on error
 */
int libfsntfs_usn_change_journal_get_offset(
     libfsntfs_usn_change_journal_t *usn_change_journal,
     off64_t *offset,
     libcerror_error_t **error )
{
	libfsntfs_internal_usn_change_journal_t *internal_usn_change_journal = NULL;
	static char *function                                                = "libfsntfs_usn_change_journal_get_offset";

	if( usn_change_journal == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid USN change journal.",
		 function );

		return( -1 );
	}
	internal_usn_change_journal = (libfsntfs_internal_usn_change_journal_t *) usn_change_journal;

	if( offset == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid offset.",
		 function );

		return( -1 );
	}
	*offset = internal_usn_change_journal->data_offset;

	return( 1 );
}

/* Reads an USN record from the USN change journal
 * Returns the number of bytes read if successful or -1 on error
 */
ssize_t libfsntfs_usn_change_journal_read_usn_record(
         libfsntfs_usn_change_journal_t *usn_change_journal,
         uint8_t *usn_record_data,
         size_t usn_record_data_size,
         libcerror_error_t **error )
{
	libfsntfs_internal_usn_change_journal_t *internal_usn_change_journal = NULL;
	static char *function                                                = "libfsntfs_usn_change_journal_read_usn_record";
	size_t read_size                                                     = 0;
	ssize_t read_count                                                   = 0;
	uint32_t usn_record_size                                             = 0;
	int read_journal_block                                               = 0;

	if( usn_change_journal == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid USN change journal.",
		 function );

		return( -1 );
	}
	internal_usn_change_journal = (libfsntfs_internal_usn_change_journal_t *) usn_change_journal;

	if( internal_usn_change_journal->journal_block_size < 60 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid USN change journal - journal block size value out of bounds.",
		 function );

		return( -1 );
	}
	if( usn_record_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid USN record data.",
		 function );

		return( -1 );
	}
	if( usn_record_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid USN record data size value out of bounds.",
		 function );

		return( -1 );
	}
	if( internal_usn_change_journal->extent_index >= internal_usn_change_journal->number_of_extents )
	{
		return( 0 );
	}
	while( usn_record_size == 0 )
	{
		while( ( ( internal_usn_change_journal->extent_flags & LIBFSNTFS_EXTENT_FLAG_IS_SPARSE ) != 0 )
		    || ( ( internal_usn_change_journal->journal_block_offset >= ( internal_usn_change_journal->journal_block_size - 60 ) )
		     &&  ( (size64_t) internal_usn_change_journal->extent_offset >= internal_usn_change_journal->extent_size ) ) )
		{
			internal_usn_change_journal->extent_index += 1;

			if( internal_usn_change_journal->extent_index >= internal_usn_change_journal->number_of_extents )
			{
				return( 0 );
			}
/* TODO make sure internal values are reset on error */
			if( libfsntfs_data_stream_get_extent_by_index(
			     internal_usn_change_journal->data_stream,
			     internal_usn_change_journal->extent_index,
			     &( internal_usn_change_journal->extent_offset ),
			     &( internal_usn_change_journal->extent_size ),
			     &( internal_usn_change_journal->extent_flags ),
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to retrieve $J data stream extent: %d.",
				 function,
				 internal_usn_change_journal->extent_index );

				return( -1 );
			}
			if( ( internal_usn_change_journal->extent_flags & LIBFSNTFS_EXTENT_FLAG_IS_SPARSE ) != 0 )
			{
				internal_usn_change_journal->data_offset += internal_usn_change_journal->extent_size;
			}
			else
			{
				if( libfsntfs_data_stream_seek_offset(
				     internal_usn_change_journal->data_stream,
				     internal_usn_change_journal->extent_offset,
				     SEEK_SET,
				     error ) != internal_usn_change_journal->extent_offset )
				{
					libcerror_error_set(
					 error,
					 LIBCERROR_ERROR_DOMAIN_IO,
					 LIBCERROR_IO_ERROR_SEEK_FAILED,
					 "%s: unable to seek offset: 0x%08" PRIx64 " in $J data stream.",
					 function,
					 internal_usn_change_journal->extent_offset );

					return( -1 );
				}
				internal_usn_change_journal->extent_size += internal_usn_change_journal->extent_offset;

				read_journal_block = 1;
			}
		}
		if( ( internal_usn_change_journal->journal_block_offset == 0 )
		 || ( internal_usn_change_journal->journal_block_offset >= ( internal_usn_change_journal->journal_block_size - 60 ) ) )
		{
			read_journal_block = 1;
		}
		if( read_journal_block != 0 )
		{
			if( (size64_t) internal_usn_change_journal->extent_offset >= internal_usn_change_journal->extent_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
				 "%s: invalid USN change journal - extent data offset value out of bounds.",
				 function );

				return( -1 );
			}
			if( memory_set(
			     internal_usn_change_journal->journal_block_data,
			     0,
			     internal_usn_change_journal->journal_block_size ) == NULL )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_MEMORY,
				 LIBCERROR_MEMORY_ERROR_SET_FAILED,
				 "%s: unable to clear journal block.",
				 function );

				return( -1 );
			}
			read_size = internal_usn_change_journal->journal_block_size;

			if( read_size > ( internal_usn_change_journal->extent_size - internal_usn_change_journal->extent_offset ) )
			{
				read_size = (size_t) ( internal_usn_change_journal->extent_size - internal_usn_change_journal->extent_offset );
			}
			read_count = libfsntfs_data_stream_read_buffer(
				      internal_usn_change_journal->data_stream,
				      internal_usn_change_journal->journal_block_data,
				      read_size,
				      error );

			if( read_count != (ssize_t) read_size )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_IO,
				 LIBCERROR_IO_ERROR_READ_FAILED,
				 "%s: unable to read journal block from $J data stream.",
				 function );

				return( -1 );
			}
			internal_usn_change_journal->extent_offset       += read_count;
			internal_usn_change_journal->journal_block_offset = 0;

/* TODO do an empty block check
			if( buffer[ 0 ] == 0 )
			{
				continue;
			}
*/
		}
		if( internal_usn_change_journal->journal_block_offset >= ( internal_usn_change_journal->journal_block_size - 60 ) )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
			 "%s: invalid USN change journal - journal block offset value out of bounds.",
			 function );

			return( -1 );
		}
		byte_stream_copy_to_uint32_little_endian(
		 &( internal_usn_change_journal->journal_block_data[ internal_usn_change_journal->journal_block_offset ] ),
		 usn_record_size );

		if( usn_record_size == 0 )
		{
			internal_usn_change_journal->data_offset          = internal_usn_change_journal->journal_block_size - internal_usn_change_journal->journal_block_offset;
			internal_usn_change_journal->journal_block_offset = internal_usn_change_journal->journal_block_size;
		}
	}
	if( ( usn_record_size < 60 )
	 || ( usn_record_size > ( internal_usn_change_journal->journal_block_size - internal_usn_change_journal->journal_block_offset ) ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid USN record size value out of bounds.",
		 function );

		return( -1 );
	}
	if( usn_record_data_size < usn_record_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: USN record data size value too small.",
		 function );

		return( -1 );
	}
	if( memory_copy(
	     usn_record_data,
	     &( internal_usn_change_journal->journal_block_data[ internal_usn_change_journal->journal_block_offset ] ),
	     (size_t) usn_record_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy USN record data.",
		 function );

		return( -1 );
	}
	internal_usn_change_journal->data_offset          += usn_record_size;
	internal_usn_change_journal->journal_block_offset += usn_record_size;

	return( (ssize_t) usn_record_size );
}

