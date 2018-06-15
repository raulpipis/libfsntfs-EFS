/*
 * Library reparse_point_values type test program
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
#include <file_stream.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "fsntfs_test_libcerror.h"
#include "fsntfs_test_libfsntfs.h"
#include "fsntfs_test_macros.h"
#include "fsntfs_test_memory.h"
#include "fsntfs_test_unused.h"

#include "../libfsntfs/libfsntfs_reparse_point_values.h"

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

/* Tests the libfsntfs_reparse_point_values_initialize function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_initialize(
     void )
{
	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	int result                                             = 0;

#if defined( HAVE_FSNTFS_TEST_MEMORY )
	int number_of_malloc_fail_tests                        = 1;
	int number_of_memset_fail_tests                        = 1;
	int test_number                                        = 0;
#endif

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          NULL,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	reparse_point_values = (libfsntfs_reparse_point_values_t *) 0x12345678UL;

	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	reparse_point_values = NULL;

#if defined( HAVE_FSNTFS_TEST_MEMORY )

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libfsntfs_reparse_point_values_initialize with malloc failing
		 */
		fsntfs_test_malloc_attempts_before_fail = test_number;

		result = libfsntfs_reparse_point_values_initialize(
		          &reparse_point_values,
		          &error );

		if( fsntfs_test_malloc_attempts_before_fail != -1 )
		{
			fsntfs_test_malloc_attempts_before_fail = -1;

			if( reparse_point_values != NULL )
			{
				libfsntfs_reparse_point_values_free(
				 &reparse_point_values,
				 NULL );
			}
		}
		else
		{
			FSNTFS_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			FSNTFS_TEST_ASSERT_IS_NULL(
			 "reparse_point_values",
			 reparse_point_values );

			FSNTFS_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
	for( test_number = 0;
	     test_number < number_of_memset_fail_tests;
	     test_number++ )
	{
		/* Test libfsntfs_reparse_point_values_initialize with memset failing
		 */
		fsntfs_test_memset_attempts_before_fail = test_number;

		result = libfsntfs_reparse_point_values_initialize(
		          &reparse_point_values,
		          &error );

		if( fsntfs_test_memset_attempts_before_fail != -1 )
		{
			fsntfs_test_memset_attempts_before_fail = -1;

			if( reparse_point_values != NULL )
			{
				libfsntfs_reparse_point_values_free(
				 &reparse_point_values,
				 NULL );
			}
		}
		else
		{
			FSNTFS_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			FSNTFS_TEST_ASSERT_IS_NULL(
			 "reparse_point_values",
			 reparse_point_values );

			FSNTFS_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#endif /* defined( HAVE_FSNTFS_TEST_MEMORY ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_free function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_free(
	          NULL,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_get_tag function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_get_tag(
     void )
{
	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	uint32_t tag                                           = 0;
	int result                                             = 0;
	int tag_is_set                                         = 0;

	/* Initialize test
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_get_tag(
	          reparse_point_values,
	          &tag,
	          &error );

	FSNTFS_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	tag_is_set = result;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_get_tag(
	          NULL,
	          &tag,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	if( tag_is_set != 0 )
	{
		result = libfsntfs_reparse_point_values_get_tag(
		          reparse_point_values,
		          NULL,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_get_utf8_substitute_name_size function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_get_utf8_substitute_name_size(
     void )
{
	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	size_t utf8_substitute_name_size                       = 0;
	int result                                             = 0;
	int utf8_substitute_name_size_is_set                   = 0;

	/* Initialize test
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_get_utf8_substitute_name_size(
	          reparse_point_values,
	          &utf8_substitute_name_size,
	          &error );

	FSNTFS_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	utf8_substitute_name_size_is_set = result;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_get_utf8_substitute_name_size(
	          NULL,
	          &utf8_substitute_name_size,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	if( utf8_substitute_name_size_is_set != 0 )
	{
		result = libfsntfs_reparse_point_values_get_utf8_substitute_name_size(
		          reparse_point_values,
		          NULL,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_get_utf8_substitute_name function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_get_utf8_substitute_name(
     void )
{
	uint8_t utf8_substitute_name[ 512 ];

	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	int result                                             = 0;
	int utf8_substitute_name_is_set                        = 0;

	/* Initialize test
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_get_utf8_substitute_name(
	          reparse_point_values,
	          utf8_substitute_name,
	          512,
	          &error );

	FSNTFS_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	utf8_substitute_name_is_set = result;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_get_utf8_substitute_name(
	          NULL,
	          utf8_substitute_name,
	          512,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	if( utf8_substitute_name_is_set != 0 )
	{
		result = libfsntfs_reparse_point_values_get_utf8_substitute_name(
		          reparse_point_values,
		          NULL,
		          512,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );

		result = libfsntfs_reparse_point_values_get_utf8_substitute_name(
		          reparse_point_values,
		          utf8_substitute_name,
		          0,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );

		result = libfsntfs_reparse_point_values_get_utf8_substitute_name(
		          reparse_point_values,
		          utf8_substitute_name,
		          (size_t) SSIZE_MAX + 1,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_get_utf16_substitute_name_size function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_get_utf16_substitute_name_size(
     void )
{
	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	size_t utf16_substitute_name_size                      = 0;
	int result                                             = 0;
	int utf16_substitute_name_size_is_set                  = 0;

	/* Initialize test
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_get_utf16_substitute_name_size(
	          reparse_point_values,
	          &utf16_substitute_name_size,
	          &error );

	FSNTFS_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	utf16_substitute_name_size_is_set = result;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_get_utf16_substitute_name_size(
	          NULL,
	          &utf16_substitute_name_size,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	if( utf16_substitute_name_size_is_set != 0 )
	{
		result = libfsntfs_reparse_point_values_get_utf16_substitute_name_size(
		          reparse_point_values,
		          NULL,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_get_utf16_substitute_name function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_get_utf16_substitute_name(
     void )
{
	uint16_t utf16_substitute_name[ 512 ];

	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	int result                                             = 0;
	int utf16_substitute_name_is_set                       = 0;

	/* Initialize test
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_get_utf16_substitute_name(
	          reparse_point_values,
	          utf16_substitute_name,
	          512,
	          &error );

	FSNTFS_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	utf16_substitute_name_is_set = result;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_get_utf16_substitute_name(
	          NULL,
	          utf16_substitute_name,
	          512,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	if( utf16_substitute_name_is_set != 0 )
	{
		result = libfsntfs_reparse_point_values_get_utf16_substitute_name(
		          reparse_point_values,
		          NULL,
		          512,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );

		result = libfsntfs_reparse_point_values_get_utf16_substitute_name(
		          reparse_point_values,
		          utf16_substitute_name,
		          0,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );

		result = libfsntfs_reparse_point_values_get_utf16_substitute_name(
		          reparse_point_values,
		          utf16_substitute_name,
		          (size_t) SSIZE_MAX + 1,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_get_utf8_print_name_size function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_get_utf8_print_name_size(
     void )
{
	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	size_t utf8_print_name_size                            = 0;
	int result                                             = 0;
	int utf8_print_name_size_is_set                        = 0;

	/* Initialize test
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_get_utf8_print_name_size(
	          reparse_point_values,
	          &utf8_print_name_size,
	          &error );

	FSNTFS_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	utf8_print_name_size_is_set = result;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_get_utf8_print_name_size(
	          NULL,
	          &utf8_print_name_size,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	if( utf8_print_name_size_is_set != 0 )
	{
		result = libfsntfs_reparse_point_values_get_utf8_print_name_size(
		          reparse_point_values,
		          NULL,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_get_utf8_print_name function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_get_utf8_print_name(
     void )
{
	uint8_t utf8_print_name[ 512 ];

	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	int result                                             = 0;
	int utf8_print_name_is_set                             = 0;

	/* Initialize test
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_get_utf8_print_name(
	          reparse_point_values,
	          utf8_print_name,
	          512,
	          &error );

	FSNTFS_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	utf8_print_name_is_set = result;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_get_utf8_print_name(
	          NULL,
	          utf8_print_name,
	          512,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	if( utf8_print_name_is_set != 0 )
	{
		result = libfsntfs_reparse_point_values_get_utf8_print_name(
		          reparse_point_values,
		          NULL,
		          512,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );

		result = libfsntfs_reparse_point_values_get_utf8_print_name(
		          reparse_point_values,
		          utf8_print_name,
		          0,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );

		result = libfsntfs_reparse_point_values_get_utf8_print_name(
		          reparse_point_values,
		          utf8_print_name,
		          (size_t) SSIZE_MAX + 1,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_get_utf16_print_name_size function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_get_utf16_print_name_size(
     void )
{
	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	size_t utf16_print_name_size                           = 0;
	int result                                             = 0;
	int utf16_print_name_size_is_set                       = 0;

	/* Initialize test
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_get_utf16_print_name_size(
	          reparse_point_values,
	          &utf16_print_name_size,
	          &error );

	FSNTFS_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	utf16_print_name_size_is_set = result;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_get_utf16_print_name_size(
	          NULL,
	          &utf16_print_name_size,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	if( utf16_print_name_size_is_set != 0 )
	{
		result = libfsntfs_reparse_point_values_get_utf16_print_name_size(
		          reparse_point_values,
		          NULL,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_reparse_point_values_get_utf16_print_name function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_reparse_point_values_get_utf16_print_name(
     void )
{
	uint16_t utf16_print_name[ 512 ];

	libcerror_error_t *error                               = NULL;
	libfsntfs_reparse_point_values_t *reparse_point_values = NULL;
	int result                                             = 0;
	int utf16_print_name_is_set                            = 0;

	/* Initialize test
	 */
	result = libfsntfs_reparse_point_values_initialize(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_reparse_point_values_get_utf16_print_name(
	          reparse_point_values,
	          utf16_print_name,
	          512,
	          &error );

	FSNTFS_TEST_ASSERT_NOT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	utf16_print_name_is_set = result;

	/* Test error cases
	 */
	result = libfsntfs_reparse_point_values_get_utf16_print_name(
	          NULL,
	          utf16_print_name,
	          512,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	if( utf16_print_name_is_set != 0 )
	{
		result = libfsntfs_reparse_point_values_get_utf16_print_name(
		          reparse_point_values,
		          NULL,
		          512,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );

		result = libfsntfs_reparse_point_values_get_utf16_print_name(
		          reparse_point_values,
		          utf16_print_name,
		          0,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );

		result = libfsntfs_reparse_point_values_get_utf16_print_name(
		          reparse_point_values,
		          utf16_print_name,
		          (size_t) SSIZE_MAX + 1,
		          &error );

		FSNTFS_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FSNTFS_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfsntfs_reparse_point_values_free(
	          &reparse_point_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "reparse_point_values",
	 reparse_point_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( reparse_point_values != NULL )
	{
		libfsntfs_reparse_point_values_free(
		 &reparse_point_values,
		 NULL );
	}
	return( 0 );
}

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain(
     int argc FSNTFS_TEST_ATTRIBUTE_UNUSED,
     wchar_t * const argv[] FSNTFS_TEST_ATTRIBUTE_UNUSED )
#else
int main(
     int argc FSNTFS_TEST_ATTRIBUTE_UNUSED,
     char * const argv[] FSNTFS_TEST_ATTRIBUTE_UNUSED )
#endif
{
	FSNTFS_TEST_UNREFERENCED_PARAMETER( argc )
	FSNTFS_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_initialize",
	 fsntfs_test_reparse_point_values_initialize );

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_free",
	 fsntfs_test_reparse_point_values_free );

	/* TODO: add tests for libfsntfs_reparse_point_values_read_data */

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_get_tag",
	 fsntfs_test_reparse_point_values_get_tag );

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_get_utf8_substitute_name_size",
	 fsntfs_test_reparse_point_values_get_utf8_substitute_name_size );

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_get_utf8_substitute_name",
	 fsntfs_test_reparse_point_values_get_utf8_substitute_name );

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_get_utf16_substitute_name_size",
	 fsntfs_test_reparse_point_values_get_utf16_substitute_name_size );

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_get_utf16_substitute_name",
	 fsntfs_test_reparse_point_values_get_utf16_substitute_name );

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_get_utf8_print_name_size",
	 fsntfs_test_reparse_point_values_get_utf8_print_name_size );

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_get_utf8_print_name",
	 fsntfs_test_reparse_point_values_get_utf8_print_name );

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_get_utf16_print_name_size",
	 fsntfs_test_reparse_point_values_get_utf16_print_name_size );

	FSNTFS_TEST_RUN(
	 "libfsntfs_reparse_point_values_get_utf16_print_name",
	 fsntfs_test_reparse_point_values_get_utf16_print_name );

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

