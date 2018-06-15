/*
 * Python object definition of the volume file entries sequence and iterator
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
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pyfsntfs_file_entry.h"
#include "pyfsntfs_libcerror.h"
#include "pyfsntfs_libfsntfs.h"
#include "pyfsntfs_python.h"
#include "pyfsntfs_volume_file_entries.h"

PySequenceMethods pyfsntfs_volume_file_entries_sequence_methods = {
	/* sq_length */
	(lenfunc) pyfsntfs_volume_file_entries_len,
	/* sq_concat */
	0,
	/* sq_repeat */
	0,
	/* sq_item */
	(ssizeargfunc) pyfsntfs_volume_file_entries_getitem,
	/* sq_slice */
	0,
	/* sq_ass_item */
	0,
	/* sq_ass_slice */
	0,
	/* sq_contains */
	0,
	/* sq_inplace_concat */
	0,
	/* sq_inplace_repeat */
	0
};

PyTypeObject pyfsntfs_volume_file_entries_type_object = {
	PyVarObject_HEAD_INIT( NULL, 0 )

	/* tp_name */
	"pyfsntfs._volume_file_entries",
	/* tp_basicsize */
	sizeof( pyfsntfs_volume_file_entries_t ),
	/* tp_itemsize */
	0,
	/* tp_dealloc */
	(destructor) pyfsntfs_volume_file_entries_free,
	/* tp_print */
	0,
	/* tp_getattr */
	0,
	/* tp_setattr */
	0,
	/* tp_compare */
	0,
	/* tp_repr */
	0,
	/* tp_as_number */
	0,
	/* tp_as_sequence */
	&pyfsntfs_volume_file_entries_sequence_methods,
	/* tp_as_mapping */
	0,
	/* tp_hash */
	0,
	/* tp_call */
	0,
	/* tp_str */
	0,
	/* tp_getattro */
	0,
	/* tp_setattro */
	0,
	/* tp_as_buffer */
	0,
	/* tp_flags */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,
	/* tp_doc */
	"internal pyfsntfs volume file entries sequence and iterator object",
	/* tp_traverse */
	0,
	/* tp_clear */
	0,
	/* tp_richcompare */
	0,
	/* tp_weaklistoffset */
	0,
	/* tp_iter */
	(getiterfunc) pyfsntfs_volume_file_entries_iter,
	/* tp_iternext */
	(iternextfunc) pyfsntfs_volume_file_entries_iternext,
	/* tp_methods */
	0,
	/* tp_members */
	0,
	/* tp_getset */
	0,
	/* tp_base */
	0,
	/* tp_dict */
	0,
	/* tp_descr_get */
	0,
	/* tp_descr_set */
	0,
	/* tp_dictoffset */
	0,
	/* tp_init */
	(initproc) pyfsntfs_volume_file_entries_init,
	/* tp_alloc */
	0,
	/* tp_new */
	0,
	/* tp_free */
	0,
	/* tp_is_gc */
	0,
	/* tp_bases */
	NULL,
	/* tp_mro */
	NULL,
	/* tp_cache */
	NULL,
	/* tp_subclasses */
	NULL,
	/* tp_weaklist */
	NULL,
	/* tp_del */
	0
};

/* Creates a new volume file entries object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pyfsntfs_volume_file_entries_new(
           pyfsntfs_volume_t *volume_object,
           PyObject* (*get_file_entry_by_index)(
                        pyfsntfs_volume_t *volume_object,
                        uint64_t file_entry_index ),
           uint64_t number_of_file_entries )
{
	pyfsntfs_volume_file_entries_t *pyfsntfs_volume_file_entries = NULL;
	static char *function                                       = "pyfsntfs_volume_file_entries_new";

	if( volume_object == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume object.",
		 function );

		return( NULL );
	}
	if( get_file_entry_by_index == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid get file entry by index function.",
		 function );

		return( NULL );
	}
	/* Make sure the volume file entries values are initialized
	 */
	pyfsntfs_volume_file_entries = PyObject_New(
	                                struct pyfsntfs_volume_file_entries,
	                                &pyfsntfs_volume_file_entries_type_object );

	if( pyfsntfs_volume_file_entries == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize volume file entries.",
		 function );

		goto on_error;
	}
	if( pyfsntfs_volume_file_entries_init(
	     pyfsntfs_volume_file_entries ) != 0 )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize volume file entries.",
		 function );

		goto on_error;
	}
	pyfsntfs_volume_file_entries->volume_object            = volume_object;
	pyfsntfs_volume_file_entries->get_file_entry_by_index = get_file_entry_by_index;
	pyfsntfs_volume_file_entries->number_of_file_entries  = number_of_file_entries;

	Py_IncRef(
	 (PyObject *) pyfsntfs_volume_file_entries->volume_object );

	return( (PyObject *) pyfsntfs_volume_file_entries );

on_error:
	if( pyfsntfs_volume_file_entries != NULL )
	{
		Py_DecRef(
		 (PyObject *) pyfsntfs_volume_file_entries );
	}
	return( NULL );
}

/* Intializes a volume file entries object
 * Returns 0 if successful or -1 on error
 */
int pyfsntfs_volume_file_entries_init(
     pyfsntfs_volume_file_entries_t *pyfsntfs_volume_file_entries )
{
	static char *function = "pyfsntfs_volume_file_entries_init";

	if( pyfsntfs_volume_file_entries == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries.",
		 function );

		return( -1 );
	}
	/* Make sure the volume file entries values are initialized
	 */
	pyfsntfs_volume_file_entries->volume_object           = NULL;
	pyfsntfs_volume_file_entries->get_file_entry_by_index = NULL;
	pyfsntfs_volume_file_entries->file_entry_index        = 0;
	pyfsntfs_volume_file_entries->number_of_file_entries  = 0;

	return( 0 );
}

/* Frees a volume file entries object
 */
void pyfsntfs_volume_file_entries_free(
      pyfsntfs_volume_file_entries_t *pyfsntfs_volume_file_entries )
{
	struct _typeobject *ob_type = NULL;
	static char *function       = "pyfsntfs_volume_file_entries_free";

	if( pyfsntfs_volume_file_entries == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries.",
		 function );

		return;
	}
	ob_type = Py_TYPE(
	           pyfsntfs_volume_file_entries );

	if( ob_type == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: missing ob_type.",
		 function );

		return;
	}
	if( ob_type->tp_free == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid ob_type - missing tp_free.",
		 function );

		return;
	}
	if( pyfsntfs_volume_file_entries->volume_object != NULL )
	{
		Py_DecRef(
		 (PyObject *) pyfsntfs_volume_file_entries->volume_object );
	}
	ob_type->tp_free(
	 (PyObject*) pyfsntfs_volume_file_entries );
}

/* The volume file entries len() function
 */
Py_ssize_t pyfsntfs_volume_file_entries_len(
            pyfsntfs_volume_file_entries_t *pyfsntfs_volume_file_entries )
{
	static char *function = "pyfsntfs_volume_file_entries_len";

	if( pyfsntfs_volume_file_entries == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries.",
		 function );

		return( -1 );
	}
	return( (Py_ssize_t) pyfsntfs_volume_file_entries->number_of_file_entries );
}

/* The volume file entries getitem() function
 */
PyObject *pyfsntfs_volume_file_entries_getitem(
           pyfsntfs_volume_file_entries_t *pyfsntfs_volume_file_entries,
           Py_ssize_t item_index )
{
	PyObject *file_entry_object = NULL;
	static char *function       = "pyfsntfs_volume_file_entries_getitem";

	if( pyfsntfs_volume_file_entries == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries.",
		 function );

		return( NULL );
	}
	if( pyfsntfs_volume_file_entries->get_file_entry_by_index == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries - missing get file entry by index function.",
		 function );

		return( NULL );
	}
	if( pyfsntfs_volume_file_entries->number_of_file_entries < 0 )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries - invalid number of file entries.",
		 function );

		return( NULL );
	}
	if( ( item_index < 0 )
	 || ( item_index >= (Py_ssize_t) pyfsntfs_volume_file_entries->number_of_file_entries ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid invalid item index value out of bounds.",
		 function );

		return( NULL );
	}
	file_entry_object = pyfsntfs_volume_file_entries->get_file_entry_by_index(
	                     pyfsntfs_volume_file_entries->volume_object,
	                     (uint64_t) item_index );

	return( file_entry_object );
}

/* The volume file entries iter() function
 */
PyObject *pyfsntfs_volume_file_entries_iter(
           pyfsntfs_volume_file_entries_t *pyfsntfs_volume_file_entries )
{
	static char *function = "pyfsntfs_volume_file_entries_iter";

	if( pyfsntfs_volume_file_entries == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries.",
		 function );

		return( NULL );
	}
	Py_IncRef(
	 (PyObject *) pyfsntfs_volume_file_entries );

	return( (PyObject *) pyfsntfs_volume_file_entries );
}

/* The volume file entries iternext() function
 */
PyObject *pyfsntfs_volume_file_entries_iternext(
           pyfsntfs_volume_file_entries_t *pyfsntfs_volume_file_entries )
{
	PyObject *file_entry_object = NULL;
	static char *function       = "pyfsntfs_volume_file_entries_iternext";

	if( pyfsntfs_volume_file_entries == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries.",
		 function );

		return( NULL );
	}
	if( pyfsntfs_volume_file_entries->get_file_entry_by_index == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries - missing get file entry by index function.",
		 function );

		return( NULL );
	}
	if( pyfsntfs_volume_file_entries->file_entry_index < 0 )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries - invalid file entry index.",
		 function );

		return( NULL );
	}
	if( pyfsntfs_volume_file_entries->number_of_file_entries < 0 )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid volume file entries - invalid number of file entries.",
		 function );

		return( NULL );
	}
	if( pyfsntfs_volume_file_entries->file_entry_index >= pyfsntfs_volume_file_entries->number_of_file_entries )
	{
		PyErr_SetNone(
		 PyExc_StopIteration );

		return( NULL );
	}
	file_entry_object = pyfsntfs_volume_file_entries->get_file_entry_by_index(
	                     pyfsntfs_volume_file_entries->volume_object,
	                     pyfsntfs_volume_file_entries->file_entry_index );

	if( file_entry_object != NULL )
	{
		pyfsntfs_volume_file_entries->file_entry_index++;
	}
	return( file_entry_object );
}

