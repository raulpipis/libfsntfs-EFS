/*
 * Directory entry functions
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

#if !defined( _LIBFSNTFS_DIRECTORY_ENTRY_H )
#define _LIBFSNTFS_DIRECTORY_ENTRY_H

#include <common.h>
#include <types.h>

#include "libfsntfs_file_name_values.h"
#include "libfsntfs_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libfsntfs_directory_entry libfsntfs_directory_entry_t;

struct libfsntfs_directory_entry
{
	/* The file reference
	 */
	uint64_t file_reference;

	/* The file name
	 */
	libfsntfs_file_name_values_t *file_name_values;

	/* The short file name
	 */
	libfsntfs_file_name_values_t *short_file_name_values;
};

int libfsntfs_directory_entry_initialize(
     libfsntfs_directory_entry_t **directory_entry,
     libcerror_error_t **error );

int libfsntfs_directory_entry_free(
     libfsntfs_directory_entry_t **directory_entry,
     libcerror_error_t **error );

int libfsntfs_directory_entry_clone(
     libfsntfs_directory_entry_t **destination_directory_entry,
     libfsntfs_directory_entry_t *source_directory_entry,
     libcerror_error_t **error );

int libfsntfs_directory_entry_compare(
     libfsntfs_directory_entry_t *first_directory_entry,
     libfsntfs_directory_entry_t *second_directory_entry,
     libcerror_error_t **error );

int libfsntfs_directory_entry_get_mft_entry_index(
     libfsntfs_directory_entry_t *directory_entry,
     uint64_t *mft_entry_index,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFSNTFS_DIRECTORY_ENTRY_H ) */

