/*
 * Python object definition of the libfsntfs USN change journal
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

#if !defined( _PYFSNTFS_USN_CHANGE_JOURNAL_H )
#define _PYFSNTFS_USN_CHANGE_JOURNAL_H

#include <common.h>
#include <types.h>

#include "pyfsntfs_libfsntfs.h"
#include "pyfsntfs_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pyfsntfs_usn_change_journal pyfsntfs_usn_change_journal_t;

struct pyfsntfs_usn_change_journal
{
	/* Python object initialization
	 */
	PyObject_HEAD

	/* The libfsntfs USN change journal
	 */
	libfsntfs_usn_change_journal_t *usn_change_journal;

	/* The volume object
	 */
	PyObject *volume_object;
};

extern PyMethodDef pyfsntfs_usn_change_journal_object_methods[];
extern PyTypeObject pyfsntfs_usn_change_journal_type_object;

PyObject *pyfsntfs_usn_change_journal_new(
           libfsntfs_usn_change_journal_t *usn_change_journal,
           PyObject *volume_object );

int pyfsntfs_usn_change_journal_init(
     pyfsntfs_usn_change_journal_t *pyfsntfs_usn_change_journal );

void pyfsntfs_usn_change_journal_free(
      pyfsntfs_usn_change_journal_t *pyfsntfs_usn_change_journal );

PyObject *pyfsntfs_usn_change_journal_get_offset(
           pyfsntfs_usn_change_journal_t *pyfsntfs_usn_change_journal,
           PyObject *arguments );

PyObject *pyfsntfs_usn_change_journal_read_usn_record(
           pyfsntfs_usn_change_journal_t *pyfsntfs_usn_change_journal,
           PyObject *arguments );

#if defined( __cplusplus )
}
#endif

#endif

