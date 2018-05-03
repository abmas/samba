/*
   Unix SMB/CIFS implementation.
   Map lease keys to file ids
   Copyright (C) Volker Lendecke 2013

   Copyright © Hewlett Packard Enterprise Development LP 2018
   Contributors - Ashok Ramakrishnan (HPE) and Paul Cerqua (HPE)
   Added support for Hyper-V over SMB 3.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "includes.h"
#include "system/filesys.h"
#include "locking/leases_db.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "util_tdb.h"
#include "ndr.h"
#include "librpc/gen_ndr/ndr_leases_db.h"
#include "tdb_wrap/tdb_wrap.h"
#include "smbd/globals.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_LOCKING

extern char * svtfs_storage_ip[];
extern int svtfs_get_lockdir_index(void);
extern void svtfs_set_lockdir_index(int);

/* the leases database handle */
#define MAX_LEASES_DBS 32
#define get_leases_db() leases_db[svtfs_get_lockdir_index()]
#define set_leases_db(value) leases_db[svtfs_get_lockdir_index()] = value

struct db_context *leases_db[MAX_LEASES_DBS] = {NULL};

extern bool smbXsrv_lookup_persistent_id(uint64_t);

void remove_stale_lease_entries(struct leases_db_value *d)
{
	uint32_t i;

	i = 0;
	while (i < d->num_files) {
		if (d->files[i].stale) {
			struct leases_db_file *m = d->files;
			m[i] = m[d->num_files-1];
			d->num_files -= 1;
		} else {
			i += 1;
		}
	}
}

static int leases_db_traverse_persist_fn(struct db_record *rec, void *_state)
{
	uint32_t i;
	TDB_DATA key,data;
	TDB_DATA value;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;
	struct leases_db_value *d;
	bool found_persistent_open = False;
	NTSTATUS status;
	struct leases_db_file *entry;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	DEBUG(1, ("leases_db_traverse_persist_fn: Entering leases_db_traverse_persist_fn\n"));

	/* Ensure this is a key record. */
	if (key.dsize != sizeof(struct leases_db_key)) {
		DEBUG(1, ("leases_db_traverse_persist_fn: Record is not a key record - key.dsize is %d\n", (int)key.dsize));
		return 0;
	}

	d = talloc(talloc_tos(), struct leases_db_value);
	if (d == NULL) {
		DEBUG(1, ("leases_db_traverse_persist_fn: talloc failed\n"));
		return 0;
	}

	blob.data = value.dptr;
	blob.length = value.dsize;

	ndr_err = ndr_pull_struct_blob_all(
		&blob, d, d,
		(ndr_pull_flags_fn_t)ndr_pull_leases_db_value);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("leases_db_traverse_persist_fn: ndr_pull_lease failed\n"));
		TALLOC_FREE(d);
		return 0;
	}

	for (i=0; i<d->num_files; i++) {
		DEBUG(1, ("leases_db_traverse_persist_fn: Loop iteration %i\n", i));
		entry = &d->files[i];
		if ( entry->open_persistent_id != UINT64_MAX && smbXsrv_lookup_persistent_id(entry->open_persistent_id) ) {
			entry->stale = false; /* [skip] in idl */
			found_persistent_open = True;
			smbXsrv_set_persistent_file_id_map(entry->open_persistent_id, entry->id);
			DEBUG(1, ("leases_db_traverse_persist_fn: Found a persistent open, retaining record for id %ld\n", entry->open_persistent_id));
		} else {
			entry->stale = true; /* [skip] in idl */
		}
	}

	if ( !found_persistent_open ) {
		DEBUG(1, ("leases_db_traverse_persist_fn: Removing record from leases.tdb\n"));
		dbwrap_record_delete(rec);
	} else {
		remove_stale_lease_entries(d);

		if (d->num_files == 0) {
			DEBUG(10, ("No used lease found\n"));
			data = make_tdb_data(NULL, 0);
		} else {
			ndr_err = ndr_push_struct_blob(
				&blob, d, d, (ndr_push_flags_fn_t)ndr_push_leases_db_value);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				TALLOC_FREE(d);
				smb_panic("ndr_push_leases_db failed");
				return 0;
			}

			data = make_tdb_data(blob.data, blob.length);
		}

		if ( data.dptr != NULL ) {
			status = dbwrap_record_store(rec, data, TDB_REPLACE);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(1, ("leases_db_traverse_persist_fn: store returned %s\n", nt_errstr(status)));
			}
		}
	}

	TALLOC_FREE(d);
	DEBUG(1, ("leases_db_traverse_persist_fn: Leaving leases_db_traverse_persist_fn\n"));

	return 0;
}

bool leases_db_init(bool read_only)
{
	char *db_path;
	NTSTATUS status;
	int index,saved_index;
	bool return_bool = true;

	index = 0;
	saved_index = svtfs_get_lockdir_index();

	svtfs_set_lockdir_index(index);
	DEBUG(5, ("leases_db_init: setting lockdir_index of 0\n"));

	while (1) {

		if (get_leases_db()) {
			return_bool = true;
			goto nextIndex;
		}

		db_path = svtfs_lock_path("leases.tdb");
		if (db_path == NULL) {
			return_bool = false;
			break;
		}

		set_leases_db(db_open(NULL, db_path, 0,
				    TDB_DEFAULT|TDB_VOLATILE|/*TDB_CLEAR_IF_FIRST|*/
				    (read_only ? 0 : TDB_TRIM_SIZE)|
				    TDB_INCOMPATIBLE_HASH,
				    read_only ? O_RDONLY : O_RDWR|O_CREAT, 0644,
				    DBWRAP_LOCK_ORDER_2, DBWRAP_FLAG_NONE));
		if (get_leases_db() == NULL) {
		    TALLOC_FREE(db_path);
			DEBUG(1, ("ERROR: Failed to initialise leases database\n"));
			return_bool = false;
			break;
		}

		if ( read_only == false ) {
			/* traverse the db and only get rid of entries not belonging to a persistent open */
			status = dbwrap_traverse(get_leases_db(), leases_db_traverse_persist_fn, NULL, NULL);

			if ( ! NT_STATUS_IS_OK(status) ) {
				TALLOC_FREE(get_leases_db());
				/* Cleanup and move on */
				DEBUG(0,("ERROR: Failed to recover persistent handle related lease entries. Cleanup and proceed.\n"));
				set_leases_db(db_open(NULL, db_path, 0,
					TDB_DEFAULT|TDB_VOLATILE|TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
					read_only?O_RDONLY:O_RDWR|O_CREAT, 0644,
					DBWRAP_LOCK_ORDER_2, DBWRAP_FLAG_NONE));
				if (!get_leases_db()) {
					TALLOC_FREE(db_path);
					DEBUG(0,("ERROR: Failed to initialise lease database\n"));
					return_bool = False;
					break;
				}
			}
		}
		TALLOC_FREE(db_path);

nextIndex:
		index++;
		if ( ( svtfs_storage_ip[index] == NULL) || ( index >= MAX_LEASES_DBS ) ) {
			DEBUG(5, ("leases_db_init: breaking with lockdir_index of %i\n", index));
			break;
		}

		DEBUG(5, ("leases_db_init: setting lockdir_index of %i\n", index));
		svtfs_set_lockdir_index(index);
	} /* end while(1) */

	DEBUG(5, ("leases_db_init: setting lockdir_index back to %d\n", saved_index));
	svtfs_set_lockdir_index(saved_index);

	return return_bool;
}

static bool leases_db_key(TALLOC_CTX *mem_ctx,
			  const struct GUID *client_guid,
			  const struct smb2_lease_key *lease_key,
			  TDB_DATA *key)
{
	struct leases_db_key db_key = {
		.client_guid = *client_guid,
		.lease_key = *lease_key };
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("%s:\n", __func__));
		NDR_PRINT_DEBUG(leases_db_key, &db_key);
	}

	ndr_err = ndr_push_struct_blob(
		&blob, mem_ctx, &db_key,
		(ndr_push_flags_fn_t)ndr_push_leases_db_key);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("%s: ndr_push_struct_blob_failed: %s\n",
			   __func__, ndr_errstr(ndr_err)));
		return false;
	}

	*key = make_tdb_data(blob.data, blob.length);
	return true;
}

NTSTATUS leases_db_add(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id,
		       const char *servicepath,
		       const char *base_name,
		       const char *stream_name,
		       uint64_t open_persistent_id)
{
	TDB_DATA db_key, db_value;
	DATA_BLOB blob;
	struct db_record *rec;
	NTSTATUS status;
	bool ok;
	struct leases_db_value new_value;
	struct leases_db_file new_file;
	struct leases_db_value *value = NULL;
	enum ndr_err_code ndr_err;

        /* We only want to do an init if the current index hasn't been initialized */
	if (get_leases_db() == NULL) {
		DEBUG(3, ("leases_db_add: calling leases_db_init()\n"));
		if (!leases_db_init(false)) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	} else {
                DEBUG(3, ("leases_db_add: DB already initialized.\n"));
        }

	ok = leases_db_key(talloc_tos(), client_guid, lease_key, &db_key);
	if (!ok) {
		DEBUG(10, ("%s: leases_db_key failed\n", __func__));
		return NT_STATUS_NO_MEMORY;
	}

	rec = dbwrap_fetch_locked(get_leases_db(), talloc_tos(), db_key);
	TALLOC_FREE(db_key.dptr);
	if (rec == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	db_value = dbwrap_record_get_value(rec);
	if (db_value.dsize != 0) {
		uint32_t i;

		DEBUG(10, ("%s: record exists\n", __func__));

		value = talloc(talloc_tos(), struct leases_db_value);
		if (value == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		blob.data = db_value.dptr;
		blob.length = db_value.dsize;

		ndr_err = ndr_pull_struct_blob_all(
			&blob, value, value,
			(ndr_pull_flags_fn_t)ndr_pull_leases_db_value);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(10, ("%s: ndr_pull_struct_blob_failed: %s\n",
				   __func__, ndr_errstr(ndr_err)));
			status = ndr_map_error2ntstatus(ndr_err);
			goto out;
		}

		/* id must be unique. */
		for (i = 0; i < value->num_files; i++) {
			if (file_id_equal(id, &value->files[i].id)) {
				status = NT_STATUS_OBJECT_NAME_COLLISION;
				goto out;
			}
		}

		value->files = talloc_realloc(value, value->files,
					struct leases_db_file,
					value->num_files + 1);
		if (value->files == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		value->files[value->num_files].id = *id;
		value->files[value->num_files].servicepath = servicepath;
		value->files[value->num_files].base_name = base_name;
		value->files[value->num_files].stream_name = stream_name;
		value->files[value->num_files].open_persistent_id = open_persistent_id;
		value->num_files += 1;

	} else {
		DEBUG(10, ("%s: new record\n", __func__));

		new_file = (struct leases_db_file) {
			.id = *id,
			.servicepath = servicepath,
			.base_name = base_name,
			.stream_name = stream_name,
			.open_persistent_id = open_persistent_id,
		};

		new_value = (struct leases_db_value) {
			.num_files = 1,
			.files = &new_file,
		};
		value = &new_value;
	}

	ndr_err = ndr_push_struct_blob(
		&blob, talloc_tos(), value,
		(ndr_push_flags_fn_t)ndr_push_leases_db_value);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("%s: ndr_push_struct_blob_failed: %s\n",
			   __func__, ndr_errstr(ndr_err)));
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("%s:\n", __func__));
		NDR_PRINT_DEBUG(leases_db_value, value);
	}

	db_value = make_tdb_data(blob.data, blob.length);

	status = dbwrap_record_store(rec, db_value, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("%s: dbwrap_record_store returned %s\n",
			   __func__, nt_errstr(status)));
	}

  out:

	if (value != &new_value) {
		TALLOC_FREE(value);
	}
	TALLOC_FREE(rec);
	return status;
}

NTSTATUS leases_db_del(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id)
{
	TDB_DATA db_key, db_value;
	struct db_record *rec;
	NTSTATUS status;
	struct leases_db_value *value;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	uint32_t i;
	bool ok;

        /* We only want to do an init if the current index hasn't been initialized */
	if (get_leases_db() == NULL) {
		DEBUG(3, ("leases_db_delete: calling leases_db_init()\n"));
		if (!leases_db_init(false)) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	} else {
                DEBUG(3, ("leases_db_delete: DB already initialized.\n"));
	}

	ok = leases_db_key(talloc_tos(), client_guid, lease_key, &db_key);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	rec = dbwrap_fetch_locked(get_leases_db(), talloc_tos(), db_key);
	TALLOC_FREE(db_key.dptr);
	if (rec == NULL) {
		return NT_STATUS_NOT_FOUND;
	}
	db_value = dbwrap_record_get_value(rec);
	if (db_value.dsize == 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	value = talloc(rec, struct leases_db_value);
	if (value == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	blob.data = db_value.dptr;
	blob.length = db_value.dsize;

	ndr_err = ndr_pull_struct_blob_all(
		&blob, value, value,
		(ndr_pull_flags_fn_t)ndr_pull_leases_db_value);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("%s: ndr_pull_struct_blob_failed: %s\n",
			   __func__, ndr_errstr(ndr_err)));
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	/* id must exist. */
	for (i = 0; i < value->num_files; i++) {
		if (file_id_equal(id, &value->files[i].id)) {
			break;
		}
	}

	if (i == value->num_files) {
		status = NT_STATUS_NOT_FOUND;
		goto out;
	}

	value->files[i] = value->files[value->num_files-1];
	value->num_files -= 1;

	if (value->num_files == 0) {
		DEBUG(10, ("%s: deleting record\n", __func__));
		status = dbwrap_record_delete(rec);
	} else {
		DEBUG(10, ("%s: updating record\n", __func__));
		ndr_err = ndr_push_struct_blob(
			&blob, rec, value,
			(ndr_push_flags_fn_t)ndr_push_leases_db_value);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(10, ("%s: ndr_push_struct_blob_failed: %s\n",
				   __func__, ndr_errstr(ndr_err)));
			status = ndr_map_error2ntstatus(ndr_err);
			goto out;
		}

		if (DEBUGLEVEL >= 10) {
			DEBUG(10, ("%s:\n", __func__));
			NDR_PRINT_DEBUG(leases_db_value, value);
		}

		db_value = make_tdb_data(blob.data, blob.length);

		status = dbwrap_record_store(rec, db_value, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("%s: dbwrap_record_store returned %s\n",
				   __func__, nt_errstr(status)));
		}
	}

  out:

	TALLOC_FREE(rec);
	return status;
}

struct leases_db_fetch_state {
	void (*parser)(uint32_t num_files,
			const struct leases_db_file *files,
			void *private_data);
	void *private_data;
	NTSTATUS status;
};

static void leases_db_parser(TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct leases_db_fetch_state *state =
		(struct leases_db_fetch_state *)private_data;
	DATA_BLOB blob = { .data = data.dptr, .length = data.dsize };
	enum ndr_err_code ndr_err;
	struct leases_db_value *value;

	value = talloc(talloc_tos(), struct leases_db_value);
	if (value == NULL) {
		state->status = NT_STATUS_NO_MEMORY;
		return;
	}

	ndr_err = ndr_pull_struct_blob_all(
		&blob, value, value,
		(ndr_pull_flags_fn_t)ndr_pull_leases_db_value);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(10, ("%s: ndr_pull_struct_blob_failed: %s\n",
			   __func__, ndr_errstr(ndr_err)));
		TALLOC_FREE(value);
		state->status = ndr_map_error2ntstatus(ndr_err);
		return;
	}

	if (DEBUGLEVEL >= 10) {
		DEBUG(10, ("%s:\n", __func__));
		NDR_PRINT_DEBUG(leases_db_value, value);
	}

	state->parser(value->num_files,
			value->files,
			state->private_data);

	TALLOC_FREE(value);
	state->status = NT_STATUS_OK;
}

NTSTATUS leases_db_parse(const struct GUID *client_guid,
			 const struct smb2_lease_key *lease_key,
			 void (*parser)(uint32_t num_files,
					const struct leases_db_file *files,
					void *private_data),
			 void *private_data)
{
	TDB_DATA db_key;
	struct leases_db_fetch_state state;
	NTSTATUS status;
	bool ok;

        /* We only want to do an init if the current index hasn't been initialized */
        if (get_leases_db() == NULL) {
                DEBUG(3, ("leases_db_parse: calling leases_db_init()\n"));
                if (!leases_db_init(true)) {
                        return NT_STATUS_INTERNAL_ERROR;
                }
        } else {
                DEBUG(3, ("leases_db_parse: DB already initialized.\n"));
        }

	ok = leases_db_key(talloc_tos(), client_guid, lease_key, &db_key);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	state = (struct leases_db_fetch_state) {
		.parser = parser,
		.private_data = private_data,
		.status = NT_STATUS_OK
	};

	status = dbwrap_parse_record(get_leases_db(), db_key, leases_db_parser,
				     &state);
	TALLOC_FREE(db_key.dptr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return state.status;
}

NTSTATUS leases_db_rename(const struct GUID *client_guid,
		       const struct smb2_lease_key *lease_key,
		       const struct file_id *id,
		       const char *servicename_new,
		       const char *filename_new,
		       const char *stream_name_new,
		       uint64_t open_persistent_id)
{
	NTSTATUS status;

	status = leases_db_del(client_guid,
				lease_key,
				id);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return leases_db_add(client_guid,
				lease_key,
				id,
				servicename_new,
				filename_new,
				stream_name_new,
				open_persistent_id);
}

NTSTATUS leases_db_copy_file_ids(TALLOC_CTX *mem_ctx,
			uint32_t num_files,
			const struct leases_db_file *files,
			struct file_id **pp_ids)
{
	uint32_t i;
	struct file_id *ids = talloc_array(mem_ctx,
				struct file_id,
				num_files);
	if (ids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_files; i++) {
		ids[i] = files[i].id;
	}
	*pp_ids = ids;
	return NT_STATUS_OK;
}
