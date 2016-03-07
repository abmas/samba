/*
   Unix SMB/CIFS implementation.

   Copyright (C) David Disseldorp 2011-2013
   Copyright (C) Richard Sharpe 2014

   Provide a simple VFS module that implements what HyperV needs in
   compression support, called fake compression.

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
#include "librpc/gen_ndr/ioctl.h"

static uint32_t fc_fs_capabilities(struct vfs_handle_struct *handle,
                                  enum timestamp_set_resolution *_ts_res)
{
       uint32_t fs_capabilities;
       enum timestamp_set_resolution ts_res;

       /* inherit default capabilities, expose compression support */
       fs_capabilities = SMB_VFS_NEXT_FS_CAPABILITIES(handle, &ts_res);
       fs_capabilities |= FILE_FILE_COMPRESSION;
       *_ts_res = ts_res;

       return fs_capabilities;
}

static NTSTATUS fc_get_compression(struct vfs_handle_struct *handle,
                                  TALLOC_CTX *mem_ctx,
                                  struct files_struct *fsp,
                                  struct smb_filename *smb_fname,
                                  uint16_t *_compression_fmt)
{
       *_compression_fmt = COMPRESSION_FORMAT_NONE;
       return NT_STATUS_OK;
}

static NTSTATUS fc_set_compression(struct vfs_handle_struct *handle,
                                  TALLOC_CTX *mem_ctx,
                                  struct files_struct *fsp,
                                  uint16_t compression_fmt)
{
       NTSTATUS status;

       if ((fsp == NULL) || (fsp->fh->fd == -1)) {
               status = NT_STATUS_INVALID_PARAMETER;
               goto err_out;
       }

       status = NT_STATUS_OK;
err_out:
       return status;
}

static struct vfs_fn_pointers fake_compression_fns = {
       .fs_capabilities_fn = fc_fs_capabilities,
       .get_compression_fn = fc_get_compression,
       .set_compression_fn = fc_set_compression,
};

NTSTATUS vfs_fake_compression_init(void);
NTSTATUS vfs_fake_compression_init(void)
{
       return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
                               "fake_compression", &fake_compression_fns);
}
