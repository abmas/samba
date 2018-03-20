/*
   Unix SMB/CIFS implementation.
   Durable Handle default VFS implementation

   Copyright (C) Stefan Metzmacher 2012
   Copyright (C) Michael Adam 2012
   Copyright (C) Volker Lendecke 2012

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "libcli/security/security.h"
#include "messages.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "serverid.h"
#include "fake_file.h"

NTSTATUS vfs_default_durable_cookie(struct files_struct *fsp,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *cookie_blob)
{
	struct connection_struct *conn = fsp->conn;
	enum ndr_err_code ndr_err;
	struct vfs_default_durable_cookie cookie;

	if (!lp_durable_handles(SNUM(conn))) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (lp_kernel_share_modes(SNUM(conn))) {
		/*
		 * We do not support durable handles
		 * if kernel share modes (flocks) are used
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (lp_kernel_oplocks(SNUM(conn))) {
		/*
		 * We do not support durable handles
		 * if kernel oplocks are used
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	if ((fsp->current_lock_count > 0) &&
	    lp_posix_locking(fsp->conn->params))
	{
		/*
		 * We do not support durable handles
		 * if the handle has posix locks.
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (fsp->is_directory) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (fsp->fh->fd == -1) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (is_ntfs_stream_smb_fname(fsp->fsp_name)) {
		/*
		 * We do not support durable handles
		 * on streams for now.
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (is_fake_file(fsp->fsp_name)) {
		/*
		 * We do not support durable handles
		 * on fake files.
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	ZERO_STRUCT(cookie);
	if (fsp->op && fsp->op->global && fsp->op->global->persistent) {
		cookie.allow_reconnect = true;
	} else {
		cookie.allow_reconnect = false;
	}
	cookie.id = fsp->file_id;
	cookie.servicepath = conn->connectpath;
	cookie.base_name = fsp->fsp_name->base_name;
	cookie.initial_allocation_size = fsp->initial_allocation_size;
	cookie.position_information = fsp->fh->position_information;
	cookie.update_write_time_triggered = fsp->update_write_time_triggered;
	cookie.update_write_time_on_close = fsp->update_write_time_on_close;
	cookie.write_time_forced = fsp->write_time_forced;
	cookie.close_write_time = fsp->close_write_time;

	cookie.stat_info.st_ex_dev = fsp->fsp_name->st.st_ex_dev;
	cookie.stat_info.st_ex_ino = fsp->fsp_name->st.st_ex_ino;
	cookie.stat_info.st_ex_mode = fsp->fsp_name->st.st_ex_mode;
	cookie.stat_info.st_ex_nlink = fsp->fsp_name->st.st_ex_nlink;
	cookie.stat_info.st_ex_uid = fsp->fsp_name->st.st_ex_uid;
	cookie.stat_info.st_ex_gid = fsp->fsp_name->st.st_ex_gid;
	cookie.stat_info.st_ex_rdev = fsp->fsp_name->st.st_ex_rdev;
	cookie.stat_info.st_ex_size = fsp->fsp_name->st.st_ex_size;
	cookie.stat_info.st_ex_atime = fsp->fsp_name->st.st_ex_atime;
	cookie.stat_info.st_ex_mtime = fsp->fsp_name->st.st_ex_mtime;
	cookie.stat_info.st_ex_ctime = fsp->fsp_name->st.st_ex_ctime;
	cookie.stat_info.st_ex_btime = fsp->fsp_name->st.st_ex_btime;
	cookie.stat_info.st_ex_calculated_birthtime = fsp->fsp_name->st.st_ex_calculated_birthtime;
	cookie.stat_info.st_ex_blksize = fsp->fsp_name->st.st_ex_blksize;
	cookie.stat_info.st_ex_blocks = fsp->fsp_name->st.st_ex_blocks;
	cookie.stat_info.st_ex_flags = fsp->fsp_name->st.st_ex_flags;
	cookie.stat_info.st_ex_mask = fsp->fsp_name->st.st_ex_mask;

	ndr_err = ndr_push_struct_blob(cookie_blob, mem_ctx, &cookie,
			(ndr_push_flags_fn_t)ndr_push_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS vfs_default_durable_disconnect(struct files_struct *fsp,
					const DATA_BLOB old_cookie,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *new_cookie)
{
	struct connection_struct *conn = fsp->conn;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	struct vfs_default_durable_cookie cookie;
	DATA_BLOB new_cookie_blob = data_blob_null;
	struct share_mode_lock *lck;
	bool ok;

	*new_cookie = data_blob_null;

	ZERO_STRUCT(cookie);

	ndr_err = ndr_pull_struct_blob(&old_cookie, talloc_tos(), &cookie,
			(ndr_pull_flags_fn_t)ndr_pull_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	if (strcmp(cookie.magic, VFS_DEFAULT_DURABLE_COOKIE_MAGIC) != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (cookie.version != VFS_DEFAULT_DURABLE_COOKIE_VERSION) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!file_id_equal(&fsp->file_id, &cookie.id)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((fsp_lease_type(fsp) & SMB2_LEASE_HANDLE) == 0) {
            if ( fsp->op->global->durable && !fsp->op->global->persistent) {
		return NT_STATUS_NOT_SUPPORTED;
            } else {
		DEBUG(3, ("vfs_default_durable_disconnect: Ignoring the fact that no lease held. Continuing with durable disconnect"));
            }
	}

	/*
	 * For now let it be simple and do not keep
	 * delete on close files durable open
	 */
	if (fsp->initial_delete_on_close) {
		return NT_STATUS_NOT_SUPPORTED;
	}
	if (fsp->delete_on_close) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (!VALID_STAT(fsp->fsp_name->st)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (!S_ISREG(fsp->fsp_name->st.st_ex_mode)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	/* Ensure any pending write time updates are done. */
	if (fsp->update_write_time_event) {
		update_write_time_handler(fsp->conn->sconn->ev_ctx,
					fsp->update_write_time_event,
					timeval_current(),
					(void *)fsp);
	}

	/*
	 * The above checks are done in mark_share_mode_disconnected() too
	 * but we want to avoid getting the lock if possible
	 */
	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck != NULL) {
		struct smb_file_time ft;

		ZERO_STRUCT(ft);

		if (fsp->write_time_forced) {
			ft.mtime = lck->data->changed_write_time;
		} else if (fsp->update_write_time_on_close) {
			if (null_timespec(fsp->close_write_time)) {
				ft.mtime = timespec_current();
			} else {
				ft.mtime = fsp->close_write_time;
			}
		}

		if (!null_timespec(ft.mtime)) {
			round_timespec(conn->ts_res, &ft.mtime);
			file_ntimes(conn, fsp->fsp_name, &ft);
		}

		ok = mark_share_mode_disconnected(lck, fsp);
		if (!ok) {
			TALLOC_FREE(lck);
		}
	}
	if (lck != NULL) {
		ok = brl_mark_disconnected(fsp);
		if (!ok) {
			TALLOC_FREE(lck);
		}
	}
	if ( lck == NULL ) {
            if ( fsp->op->global->durable && !fsp->op->global->persistent) {
	        return NT_STATUS_NOT_SUPPORTED;
            } else {
		/* Now that we have taken care of the durable case, I think this can be removed. For resilient and persistent, it is */
		/* entirely legit to have no share mode locks on disconnect. If there are no locks to preserve, none will be preserved */
                DEBUG(1, ("vfs_default_durable_disconnect: Ignoring share mode lock check and continuing with durable disconnect\n"));
            }
	}

        if ( lck ) TALLOC_FREE(lck);

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ZERO_STRUCT(cookie);
	cookie.allow_reconnect = true;
	cookie.id = fsp->file_id;
	cookie.servicepath = conn->connectpath;
	cookie.base_name = fsp->fsp_name->base_name;
	cookie.initial_allocation_size = fsp->initial_allocation_size;
	cookie.position_information = fsp->fh->position_information;
	cookie.update_write_time_triggered = fsp->update_write_time_triggered;
	cookie.update_write_time_on_close = fsp->update_write_time_on_close;
	cookie.write_time_forced = fsp->write_time_forced;
	cookie.close_write_time = fsp->close_write_time;

	cookie.stat_info.st_ex_dev = fsp->fsp_name->st.st_ex_dev;
	cookie.stat_info.st_ex_ino = fsp->fsp_name->st.st_ex_ino;
	cookie.stat_info.st_ex_mode = fsp->fsp_name->st.st_ex_mode;
	cookie.stat_info.st_ex_nlink = fsp->fsp_name->st.st_ex_nlink;
	cookie.stat_info.st_ex_uid = fsp->fsp_name->st.st_ex_uid;
	cookie.stat_info.st_ex_gid = fsp->fsp_name->st.st_ex_gid;
	cookie.stat_info.st_ex_rdev = fsp->fsp_name->st.st_ex_rdev;
	cookie.stat_info.st_ex_size = fsp->fsp_name->st.st_ex_size;
	cookie.stat_info.st_ex_atime = fsp->fsp_name->st.st_ex_atime;
	cookie.stat_info.st_ex_mtime = fsp->fsp_name->st.st_ex_mtime;
	cookie.stat_info.st_ex_ctime = fsp->fsp_name->st.st_ex_ctime;
	cookie.stat_info.st_ex_btime = fsp->fsp_name->st.st_ex_btime;
	cookie.stat_info.st_ex_calculated_birthtime = fsp->fsp_name->st.st_ex_calculated_birthtime;
	cookie.stat_info.st_ex_blksize = fsp->fsp_name->st.st_ex_blksize;
	cookie.stat_info.st_ex_blocks = fsp->fsp_name->st.st_ex_blocks;
	cookie.stat_info.st_ex_flags = fsp->fsp_name->st.st_ex_flags;
	cookie.stat_info.st_ex_mask = fsp->fsp_name->st.st_ex_mask;

	ndr_err = ndr_push_struct_blob(&new_cookie_blob, mem_ctx, &cookie,
			(ndr_push_flags_fn_t)ndr_push_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	status = fd_close(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&new_cookie_blob);
		return status;
	}

	*new_cookie = new_cookie_blob;
	return NT_STATUS_OK;
}


/**
 * Check whether a cookie-stored struct info is the same
 * as a given SMB_STRUCT_STAT, as coming with the fsp.
 */
static bool vfs_default_durable_reconnect_check_stat(
				struct vfs_default_durable_stat *cookie_st,
				SMB_STRUCT_STAT *fsp_st,
				const char *name)
{
	int ret;

	if (cookie_st->st_ex_dev != fsp_st->st_ex_dev) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_dev",
			  (unsigned long long)cookie_st->st_ex_dev,
			  (unsigned long long)fsp_st->st_ex_dev));
		return false;
	}

	if (cookie_st->st_ex_ino != fsp_st->st_ex_ino) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_ino",
			  (unsigned long long)cookie_st->st_ex_ino,
			  (unsigned long long)fsp_st->st_ex_ino));
		return false;
	}

	if (cookie_st->st_ex_mode != fsp_st->st_ex_mode) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_mode",
			  (unsigned long long)cookie_st->st_ex_mode,
			  (unsigned long long)fsp_st->st_ex_mode));
		return false;
	}

	if (cookie_st->st_ex_nlink != fsp_st->st_ex_nlink) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_nlink",
			  (unsigned long long)cookie_st->st_ex_nlink,
			  (unsigned long long)fsp_st->st_ex_nlink));
		return false;
	}

	if (cookie_st->st_ex_uid != fsp_st->st_ex_uid) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_uid",
			  (unsigned long long)cookie_st->st_ex_uid,
			  (unsigned long long)fsp_st->st_ex_uid));
		return false;
	}

	if (cookie_st->st_ex_gid != fsp_st->st_ex_gid) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_gid",
			  (unsigned long long)cookie_st->st_ex_gid,
			  (unsigned long long)fsp_st->st_ex_gid));
		return false;
	}

	if (cookie_st->st_ex_rdev != fsp_st->st_ex_rdev) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_rdev",
			  (unsigned long long)cookie_st->st_ex_rdev,
			  (unsigned long long)fsp_st->st_ex_rdev));
		return false;
	}

	if (cookie_st->st_ex_size != fsp_st->st_ex_size) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_size",
			  (unsigned long long)cookie_st->st_ex_size,
			  (unsigned long long)fsp_st->st_ex_size));
		return false;
	}

	ret = timespec_compare(&cookie_st->st_ex_atime,
			       &fsp_st->st_ex_atime);
	if (ret != 0) {
		struct timeval tc, ts;
		tc = convert_timespec_to_timeval(cookie_st->st_ex_atime);
		ts = convert_timespec_to_timeval(fsp_st->st_ex_atime);

		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:'%s' != stat:'%s', "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_atime",
			  timeval_string(talloc_tos(), &tc, true),
			  timeval_string(talloc_tos(), &ts, true)));
		return false;
	}

	ret = timespec_compare(&cookie_st->st_ex_mtime,
			       &fsp_st->st_ex_mtime);
	if (ret != 0) {
		struct timeval tc, ts;
		tc = convert_timespec_to_timeval(cookie_st->st_ex_mtime);
		ts = convert_timespec_to_timeval(fsp_st->st_ex_mtime);

		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:'%s' != stat:'%s', "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_mtime",
			  timeval_string(talloc_tos(), &tc, true),
			  timeval_string(talloc_tos(), &ts, true)));
		return false;
	}

	ret = timespec_compare(&cookie_st->st_ex_ctime,
			       &fsp_st->st_ex_ctime);
	if (ret != 0) {
		struct timeval tc, ts;
		tc = convert_timespec_to_timeval(cookie_st->st_ex_ctime);
		ts = convert_timespec_to_timeval(fsp_st->st_ex_ctime);

		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:'%s' != stat:'%s', "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_ctime",
			  timeval_string(talloc_tos(), &tc, true),
			  timeval_string(talloc_tos(), &ts, true)));
		return false;
	}

	ret = timespec_compare(&cookie_st->st_ex_btime,
			       &fsp_st->st_ex_btime);
	if (ret != 0) {
		struct timeval tc, ts;
		tc = convert_timespec_to_timeval(cookie_st->st_ex_btime);
		ts = convert_timespec_to_timeval(fsp_st->st_ex_btime);

		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:'%s' != stat:'%s', "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_btime",
			  timeval_string(talloc_tos(), &tc, true),
			  timeval_string(talloc_tos(), &ts, true)));
		return false;
	}

	if (cookie_st->st_ex_calculated_birthtime !=
	    fsp_st->st_ex_calculated_birthtime)
	{
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_calculated_birthtime",
			  (unsigned long long)cookie_st->st_ex_calculated_birthtime,
			  (unsigned long long)fsp_st->st_ex_calculated_birthtime));
		return false;
	}

	if (cookie_st->st_ex_blksize != fsp_st->st_ex_blksize) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_blksize",
			  (unsigned long long)cookie_st->st_ex_blksize,
			  (unsigned long long)fsp_st->st_ex_blksize));
		return false;
	}

	if (cookie_st->st_ex_blocks != fsp_st->st_ex_blocks) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_blocks",
			  (unsigned long long)cookie_st->st_ex_blocks,
			  (unsigned long long)fsp_st->st_ex_blocks));
		return false;
	}

	if (cookie_st->st_ex_flags != fsp_st->st_ex_flags) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_flags",
			  (unsigned long long)cookie_st->st_ex_flags,
			  (unsigned long long)fsp_st->st_ex_flags));
		return false;
	}

	if (cookie_st->st_ex_mask != fsp_st->st_ex_mask) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_mask",
			  (unsigned long long)cookie_st->st_ex_mask,
			  (unsigned long long)fsp_st->st_ex_mask));
		return false;
	}

	return true;
}

NTSTATUS vfs_default_durable_reconnect(struct connection_struct *conn,
				       struct smb_request *smb1req,
				       struct smbXsrv_open *op,
				       const DATA_BLOB old_cookie,
				       TALLOC_CTX *mem_ctx,
				       files_struct **result,
				       DATA_BLOB *new_cookie)
{
	struct share_mode_lock *lck = NULL;
	struct share_mode_entry *e = NULL;
	struct files_struct *fsp = NULL;
	NTSTATUS status;
	bool ok;
	int ret = 0,i = 0;
	int flags = 0;
	struct file_id file_id;
	struct smb_filename *smb_fname = NULL;
	enum ndr_err_code ndr_err;
	struct vfs_default_durable_cookie cookie;
	DATA_BLOB new_cookie_blob = data_blob_null;

	*result = NULL;
	*new_cookie = data_blob_null;

	if (!lp_durable_handles(SNUM(conn))) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	/*
	 * the checks for kernel oplocks
	 * and similar things are done
	 * in the vfs_default_durable_cookie()
	 * call below.
	 */

	ZERO_STRUCT(cookie);

	ndr_err = ndr_pull_struct_blob(&old_cookie, talloc_tos(), &cookie,
			(ndr_pull_flags_fn_t)ndr_pull_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DEBUG(1,("ndr_pull_struct_blob error. returning %s\n", nt_errstr(status)));
		return status;
	}

	if (strcmp(cookie.magic, VFS_DEFAULT_DURABLE_COOKIE_MAGIC) != 0) {
		DEBUG(1,("cookie.magic error. returning NT_STATUS_INVALID_PARAMETER\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (cookie.version != VFS_DEFAULT_DURABLE_COOKIE_VERSION) {
		DEBUG(1,("cookie.version error. returning NT_STATUS_INVALID_PARAMETER\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!cookie.allow_reconnect) {
		DEBUG(1,("cookie.allow_reconnect not set. returning NT_STATUS_OBJECT_NAME_NOT_FOUND\n"));
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (strcmp(cookie.servicepath, conn->connectpath) != 0) {
		DEBUG(1,("cookie.servicepath doesn't match. returning NT_STATUS_OBJECT_NAME_NOT_FOUND\n"));
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* Create an smb_filename with stream_name == NULL. */
	smb_fname = synthetic_smb_fname(talloc_tos(), cookie.base_name,
					NULL, NULL);
	if (smb_fname == NULL) {
		DEBUG(1,("smb_fname NULL, returning NT_STATUS_NO_MEMORY\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* SVT-HPE: Add a retry loop here. In case it takes time to activate hive */
	for (i=0; i < 5; i++)
	{
		ret = SMB_VFS_LSTAT(conn, smb_fname);
		if (ret == -1) {
			status = map_nt_error_from_unix_common(errno);
			DEBUG(1, ("Unable to lstat stream: %s => %s\n",
			  	smb_fname_str_dbg(smb_fname),
			  	nt_errstr(status)));
			if (!(NT_STATUS_EQUAL(status,NT_STATUS_IO_TIMEOUT) || NT_STATUS_EQUAL(status,STATUS_MORE_ENTRIES))) {
				/* Only retry if return code is EAGAIN or ETIMEDOUT */
				break;
			}
		} else {
			break;
		}
	}
	if (ret == -1 ) return status;

	if (!S_ISREG(smb_fname->st.st_ex_mode)) {
		DEBUG(1,("smb_fname->st.st_ex_mode incorrect\n"));
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	if (!file_id_equal(&cookie.id, &file_id)) {
		DEBUG(1,("file id mismatch cookie = %llu, stat = %llu\n",(unsigned long long)cookie.id.devid, (unsigned long long)file_id.devid));
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/*
	 * 1. check entry in locking.tdb
	 */

	lck = get_existing_share_mode_lock(mem_ctx, file_id);

        if (lck == NULL) {
                if ( op->global->durable && !op->global->persistent) {
                       DEBUG(1, ("vfs_default_durable_reconnect: share-mode lock "
                               "not obtained from db\n"));
                       return NT_STATUS_OBJECT_NAME_NOT_FOUND;
                } else {
                       DEBUG(1, ("vfs_default_durable_reconnect: share-mode lock "
                               "not obtained from db, Ignoring...\n"));
                       goto PROCEEDOPEN;
                }
        }

        if (lck->data->num_share_modes == 0) {
                if ( op->global->durable && !op->global->persistent) {
                       DEBUG(1, ("vfs_default_durable_reconnect: Error: no share-mode "
                               "entry in existing share mode lock\n"));
                       TALLOC_FREE(lck);
                       return NT_STATUS_INTERNAL_DB_ERROR;
                } else {
			/* Ok to not have any share mode locks for resilient and persistent? */
                       DEBUG(1, ("vfs_default_durable_reconnect: Error: no share-mode "
                               "entry in existing share mode lock, Ignoring...\n"));
                       goto PROCEEDOPEN;
                }
        }

        for (i=0; i<lck->data->num_share_modes; i++) {
                e = &lck->data->share_modes[i];
                DEBUG(10, ("vfs_default_durable_reconnect: Processing share mode entry with inode %lu and share_file_id %lu\n", file_id.inode, e->share_file_id));
                if (e->share_file_id != op->global->open_persistent_id) {
                       /* When a share mode entry is marked disconnected, the share_file_id is set to open_persistent_id*/
                       /* This could have been a share mode entry already reconnected */
                       e = NULL;
                       continue;
                }
                DEBUG(10, ("vfs_default_durable_reconnect: Matched share mode entry with inode %lu and share_file_id %lu\n", file_id.inode, e->share_file_id));
	        break;
        }
        if ( e == NULL ) {
                DEBUG(1, ("vfs_default_durable_reconnect: Error : no share mode entries available to reconnect, Ignoring...\n"));
                goto PROCEEDOPEN;
        }

	if ((e->access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) &&
	    !CAN_WRITE(conn))
	{
		DEBUG(1, ("vfs_default_durable_reconnect: denying durable "
			  "share[%s] is not writeable anymore\n",
			  lp_servicename(talloc_tos(), SNUM(conn))));
		TALLOC_FREE(lck);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/*
	 * 2. proceed with opening file
	 */
PROCEEDOPEN:
	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("vfs_default_durable_reconnect: failed to create "
			  "new fsp: %s\n", nt_errstr(status)));
		if (lck) TALLOC_FREE(lck);
		return status;
	}

	fsp->fh->gen_id = smbXsrv_open_hash(op);
	fsp->file_id = file_id;
	fsp->file_pid = smb1req->smbpid;
	fsp->vuid = smb1req->vuid;

        if (e != NULL) {
		fsp->fh->private_options = e->private_options;
		fsp->open_time = e->time;
		fsp->access_mask = e->access_mask;
		fsp->share_access = e->share_access;
		fsp->oplock_type = e->op_type;
	}

	fsp->can_read = ((fsp->access_mask & (FILE_READ_DATA)) != 0);
	fsp->can_write = ((fsp->access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) != 0);
	fsp->fnum = op->local_id;

	/*
	 * TODO:
	 * Do we need to store the modified flag in the DB?
	 */
	fsp->modified = false;
	/*
	 * no durables for directories
	 */
	fsp->is_directory = false;
	/*
	 * For normal files, can_lock == !is_directory
	 */
	fsp->can_lock = true;
	/*
	 * We do not support aio write behind for smb2
	 */
	fsp->aio_write_behind = false;

	if (fsp->oplock_type == LEASE_OPLOCK) {
		struct share_mode_lease *l = &lck->data->leases[e->lease_idx];
		struct smb2_lease_key key;

		key.data[0] = l->lease_key.data[0];
		key.data[1] = l->lease_key.data[1];

		fsp->lease = find_fsp_lease(fsp, &key, l);
		if (fsp->lease == NULL) {
			if (lck) TALLOC_FREE(lck);
			fsp_free(fsp);
			DEBUG(1,("find_fsp_lease returned NULL, failing with NT_STATUS_NO_MEMORY\n"));
			return NT_STATUS_NO_MEMORY;
		}

		/*
		 * Ensure the existing client guid matches the
		 * stored one in the share_mode_lease.
		 */
		if (!GUID_equal(fsp_client_guid(fsp),
				&l->client_guid)) {
			if (lck) TALLOC_FREE(lck);
			fsp_free(fsp);
			DEBUG(1,("GUID_equal returned false, failing with NT_STATUS_OBJECT_NAME_NOT_FOUND\n"));
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
	}

	fsp->initial_allocation_size = cookie.initial_allocation_size;
	fsp->fh->position_information = cookie.position_information;
	fsp->update_write_time_triggered = cookie.update_write_time_triggered;
	fsp->update_write_time_on_close = cookie.update_write_time_on_close;
	fsp->write_time_forced = cookie.write_time_forced;
	fsp->close_write_time = cookie.close_write_time;

	status = fsp_set_smb_fname(fsp, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		if (lck) TALLOC_FREE(lck);
		fsp_free(fsp);
		DEBUG(1, ("vfs_default_durable_reconnect: "
			  "fsp_set_smb_fname failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	op->compat = fsp;
	fsp->op = op;

        if (e != NULL) {
	        e->pid = messaging_server_id(conn->sconn->msg_ctx);
	        e->op_mid = smb1req->mid;
	        e->share_file_id = fsp->fh->gen_id;
        }

	ok = brl_reconnect_disconnected(fsp);
	if (!ok) {
		status = NT_STATUS_INTERNAL_ERROR;
		DEBUG(1, ("vfs_default_durable_reconnect: "
			  "failed to reopen brlocks: %s\n",
			  nt_errstr(status)));
		if (lck) TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	/*
	 * TODO: properly calculate open flags
	 */
	if (fsp->can_write && fsp->can_read) {
		flags = O_RDWR;
	} else if (fsp->can_write) {
		flags = O_WRONLY;
	} else if (fsp->can_read) {
		flags = O_RDONLY;
	}

	status = fd_open(conn, fsp, flags, 0 /* mode */);
	if (!NT_STATUS_IS_OK(status)) {
		if (lck) TALLOC_FREE(lck);
		DEBUG(1, ("vfs_default_durable_reconnect: failed to open "
			  "file: %s\n", nt_errstr(status)));
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	/*
	 * We now check the stat info stored in the cookie against
	 * the current stat data from the file we just opened.
	 * If any detail differs, we deny the durable reconnect,
	 * because in that case it is very likely that someone
	 * opened the file while the handle was disconnected,
	 * which has to be interpreted as an oplock break.
	 */

	ret = SMB_VFS_FSTAT(fsp, &fsp->fsp_name->st);
	if (ret == -1) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(1, ("Unable to fstat stream: %s => %s\n",
			  smb_fname_str_dbg(smb_fname),
			  nt_errstr(status)));
		ret = SMB_VFS_CLOSE(fsp);
		if (ret == -1) {
			DEBUG(1, ("vfs_default_durable_reconnect: "
				  "SMB_VFS_CLOSE failed (%s) - leaking file "
				  "descriptor\n", strerror(errno)));
		}
		if (lck) TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	if (!S_ISREG(fsp->fsp_name->st.st_ex_mode)) {
		DEBUG(1, ("S_ISREG check failed, returning NT_STATUS_OBJECT_NAME_NOT_FOUND\n"));
		ret = SMB_VFS_CLOSE(fsp);
		if (ret == -1) {
			DEBUG(1, ("vfs_default_durable_reconnect: "
				  "SMB_VFS_CLOSE failed (%s) - leaking file "
				  "descriptor\n", strerror(errno)));
		}
		if (lck) TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);
	if (!file_id_equal(&cookie.id, &file_id)) {
		DEBUG(1, ("file_id_equal check failed, returning NT_STATUS_OBJECT_NAME_NOT_FOUND\n"));
		ret = SMB_VFS_CLOSE(fsp);
		if (ret == -1) {
			DEBUG(0, ("vfs_default_durable_reconnect: "
				  "SMB_VFS_CLOSE failed (%s) - leaking file "
				  "descriptor\n", strerror(errno)));
		}
		if (lck) TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	status = set_file_oplock(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("vfs_default_durable_reconnect failed to set oplock "
			  "after opening file: %s\n", nt_errstr(status)));
		ret = SMB_VFS_CLOSE(fsp);
		if (ret == -1) {
			DEBUG(0, ("vfs_default_durable_reconnect: "
				  "SMB_VFS_CLOSE failed (%s) - leaking file "
				  "descriptor\n", strerror(errno)));
		}
		if (lck) TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	status = vfs_default_durable_cookie(fsp, mem_ctx, &new_cookie_blob);
	if (!NT_STATUS_IS_OK(status)) {
		if (lck) TALLOC_FREE(lck);
		DEBUG(1, ("vfs_default_durable_reconnect: "
			  "vfs_default_durable_cookie - %s\n",
			  nt_errstr(status)));
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	smb1req->chain_fsp = fsp;
	smb1req->smb2req->compat_chain_fsp = fsp;

	DEBUG(10, ("vfs_default_durable_reconnect: opened file '%s'\n",
		   fsp_str_dbg(fsp)));

	/*
	 * release the sharemode lock: this writes the changes
	 */
	if (lck) {
		lck->data->modified = true;
		TALLOC_FREE(lck);
	}

	*result = fsp;
	*new_cookie = new_cookie_blob;

	return NT_STATUS_OK;
}
