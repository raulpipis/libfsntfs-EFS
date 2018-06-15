/*
 * Volume name attribute ($VOLUME_NAME) values functions
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
#include <memory.h>
#include <narrow_string.h>
#include <system_string.h>
#include <types.h>
#include <wide_string.h>

#include "libfsntfs_libcerror.h"
#include "libfsntfs_libcnotify.h"
#include "libfsntfs_libuna.h"
#include "libfsntfs_volume_name_values.h"

/* Creates volume name values
 * Make sure the value volume_name_values is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_volume_name_values_initialize(
     libfsntfs_volume_name_values_t **volume_name_values,
     libcerror_error_t **error )
{
	static char *function = "libfsntfs_volume_name_values_initialize";

	if( volume_name_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid volume name values.",
		 function );

		return( -1 );
	}
	if( *volume_name_values != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid volume name values value already set.",
		 function );

		return( -1 );
	}
	*volume_name_values = memory_allocate_structure(
	                       libfsntfs_volume_name_values_t );

	if( *volume_name_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create volume name values.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     *volume_name_values,
	     0,
	     sizeof( libfsntfs_volume_name_values_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear volume name values.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	if( *volume_name_values != NULL )
	{
		memory_free(
		 *volume_name_values );

		*volume_name_values = NULL;
	}
	return( -1 );
}

/* Frees volume name values
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_volume_name_values_free(
     libfsntfs_volume_name_values_t **volume_name_values,
     libcerror_error_t **error )
{
	static char *function = "libfsntfs_volume_name_values_free";

	if( volume_name_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid volume name values.",
		 function );

		return( -1 );
	}
	if( *volume_name_values != NULL )
	{
		if( ( *volume_name_values )->name != NULL )
		{
			memory_free(
			 ( *volume_name_values )->name );
		}
		memory_free(
		 *volume_name_values );

		*volume_name_values = NULL;
	}
	return( 1 );
}

/* Reads the volume name values
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_volume_name_values_read_data(
     libfsntfs_volume_name_values_t *volume_name_values,
     const uint8_t *data,
     size_t data_size,
     libcerror_error_t **error )
{
	static char *function            = "libfsntfs_volume_name_values_read_data";

#if defined( HAVE_DEBUG_OUTPUT )
	system_character_t *value_string = NULL;
	size_t value_string_size         = 0;
	int result                       = 0;
#endif

	if( volume_name_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid volume name values.",
		 function );

		return( -1 );
	}
	/* The size of the data can be 0 if the name is not set.
	 */
	if( data_size == 0 )
	{
		return( 1 );
	}
	if( data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_MISSING,
		 "%s: invalid data.",
		 function );

		goto on_error;
	}
	if( data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid data size value out of bounds.",
		 function );

		goto on_error;
	}
#if defined( HAVE_DEBUG_OUTPUT )
	if( libcnotify_verbose != 0 )
	{
		libcnotify_printf(
		 "%s: volume name data:\n",
		 function );
		libcnotify_print_data(
		 data,
		 data_size,
		 0 );
	}
#endif
	if( data_size > 0 )
	{
		volume_name_values->name = (uint8_t *) memory_allocate(
		                                        sizeof( uint8_t ) * data_size );

		if( volume_name_values->name == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create name.",
			 function );

			goto on_error;
		}
		volume_name_values->name_size = data_size;

		if( memory_copy(
		     volume_name_values->name,
		     data,
		     volume_name_values->name_size ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy volume name.",
			 function );

			goto on_error;
		}
#if defined( HAVE_DEBUG_OUTPUT )
		if( libcnotify_verbose != 0 )
		{
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
			result = libuna_utf16_string_size_from_utf16_stream(
				  volume_name_values->name,
				  volume_name_values->name_size,
				  LIBUNA_ENDIAN_LITTLE,
				  &value_string_size,
				  error );
#else
			result = libuna_utf8_string_size_from_utf16_stream(
				  volume_name_values->name,
				  volume_name_values->name_size,
				  LIBUNA_ENDIAN_LITTLE,
				  &value_string_size,
				  error );
#endif
			if( result != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
				 "%s: unable to determine size of name string.",
				 function );

				goto on_error;
			}
			value_string = system_string_allocate(
			                value_string_size );

			if( value_string == NULL )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_MEMORY,
				 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
				 "%s: unable to create name string.",
				 function );

				goto on_error;
			}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
			result = libuna_utf16_string_copy_from_utf16_stream(
				  (libuna_utf16_character_t *) value_string,
				  value_string_size,
				  volume_name_values->name,
				  volume_name_values->name_size,
				  LIBUNA_ENDIAN_LITTLE,
				  error );
#else
			result = libuna_utf8_string_copy_from_utf16_stream(
				  (libuna_utf8_character_t *) value_string,
				  value_string_size,
				  volume_name_values->name,
				  volume_name_values->name_size,
				  LIBUNA_ENDIAN_LITTLE,
				  error );
#endif
			if( result != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_RUNTIME,
				 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
				 "%s: unable to set name string.",
				 function );

				goto on_error;
			}
			libcnotify_printf(
			 "%s: name\t\t\t\t: %" PRIs_SYSTEM "\n",
			 function,
			 value_string );

			memory_free(
			 value_string );

			value_string = NULL;

			libcnotify_printf(
			 "\n" );
		}
#endif
	}
	return( 1 );

on_error:
#if defined( HAVE_DEBUG_OUTPUT )
	if( value_string != NULL )
	{
		memory_free(
		 value_string );
	}
#endif
	if( volume_name_values->name != NULL )
	{
		memory_free(
		 volume_name_values->name );

		volume_name_values->name = NULL;
	}
	volume_name_values->name_size = 0;

	return( -1 );
}

/* Retrieves the size of the UTF-8 encoded name
 * The returned size includes the end of string character
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_volume_name_values_get_utf8_name_size(
     libfsntfs_volume_name_values_t *volume_name_values,
     size_t *utf8_name_size,
     libcerror_error_t **error )
{
	static char *function = "libfsntfs_volume_name_values_get_utf8_name_size";

	if( volume_name_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid volume name values.",
		 function );

		return( -1 );
	}
	if( volume_name_values->name_size == 0 )
	{
		if( utf8_name_size == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid UTF-8 name size.",
			 function );

			return( -1 );
		}
		*utf8_name_size = 0;
	}
	else
	{
		if( libuna_utf8_string_size_from_utf16_stream(
		     volume_name_values->name,
		     (size_t) volume_name_values->name_size,
		     LIBUNA_ENDIAN_LITTLE,
		     utf8_name_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve UTF-8 string size.",
			 function );

			return( -1 );
		}
	}
	return( 1 );
}

/* Retrieves the UTF-8 encoded name
 * The size should include the end of string character
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_volume_name_values_get_utf8_name(
     libfsntfs_volume_name_values_t *volume_name_values,
     uint8_t *utf8_name,
     size_t utf8_name_size,
     libcerror_error_t **error )
{
	static char *function = "libfsntfs_volume_name_values_get_utf8_name";

	if( volume_name_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid volume name values.",
		 function );

		return( -1 );
	}
	if( volume_name_values->name_size == 0 )
	{
		if( utf8_name == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid UTF-8 name.",
			 function );

			return( -1 );
		}
		if( utf8_name_size > (size_t) SSIZE_MAX )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM,
			 "%s: invalid UTF-8 name size value exceeds maximum.",
			 function );

			return( -1 );
		}
		if( utf8_name_size < 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: UTF-8 name size value too small.",
			 function );

			return( -1 );
		}
		utf8_name[ 0 ] = 0;
	}
	else
	{
		if( libuna_utf8_string_copy_from_utf16_stream(
		     utf8_name,
		     utf8_name_size,
		     volume_name_values->name,
		     (size_t) volume_name_values->name_size,
		     LIBUNA_ENDIAN_LITTLE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to retrieve UTF-8 string.",
			 function );

			return( -1 );
		}
	}
	return( 1 );
}

/* Retrieves the size of the UTF-16 encoded name
 * The returned size includes the end of string character
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_volume_name_values_get_utf16_name_size(
     libfsntfs_volume_name_values_t *volume_name_values,
     size_t *utf16_name_size,
     libcerror_error_t **error )
{
	static char *function = "libfsntfs_volume_name_values_get_utf16_name_size";

	if( volume_name_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid volume name values.",
		 function );

		return( -1 );
	}
	if( volume_name_values->name_size == 0 )
	{
		if( utf16_name_size == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid UTF-16 name size.",
			 function );

			return( -1 );
		}
		*utf16_name_size = 0;
	}
	else
	{
		if( libuna_utf16_string_size_from_utf16_stream(
		     volume_name_values->name,
		     (size_t) volume_name_values->name_size,
		     LIBUNA_ENDIAN_LITTLE,
		     utf16_name_size,
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
	}
	return( 1 );
}

/* Retrieves the UTF-16 encoded name
 * The size should include the end of string character
 * Returns 1 if successful or -1 on error
 */
int libfsntfs_volume_name_values_get_utf16_name(
     libfsntfs_volume_name_values_t *volume_name_values,
     uint16_t *utf16_name,
     size_t utf16_name_size,
     libcerror_error_t **error )
{
	static char *function = "libfsntfs_volume_name_values_get_utf16_name";

	if( volume_name_values == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid volume name values.",
		 function );

		return( -1 );
	}
	if( volume_name_values->name_size == 0 )
	{
		if( utf16_name == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
			 "%s: invalid UTF-16 name.",
			 function );

			return( -1 );
		}
		if( utf16_name_size > (size_t) SSIZE_MAX )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM,
			 "%s: invalid UTF-16 name size value exceeds maximum.",
			 function );

			return( -1 );
		}
		if( utf16_name_size < 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
			 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
			 "%s: UTF-16 name size value too small.",
			 function );

			return( -1 );
		}
		utf16_name[ 0 ] = 0;
	}
	else
	{
		if( libuna_utf16_string_copy_from_utf16_stream(
		     utf16_name,
		     utf16_name_size,
		     volume_name_values->name,
		     (size_t) volume_name_values->name_size,
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
	}
	return( 1 );
}

