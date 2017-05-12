/*
   Unix SMB/CIFS implementation.
   TDB wrap functions

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007

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

#include "replace.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "tdb_wrap.h"
#include "system/filesys.h"

/*
 Log tdb messages via DEBUG().
*/
static void tdb_wrap_log(TDB_CONTEXT *tdb, enum tdb_debug_level level,
			 const char *format, ...) PRINTF_ATTRIBUTE(3,4);

static void tdb_wrap_log(TDB_CONTEXT *tdb, enum tdb_debug_level level,
			 const char *format, ...)
{
	va_list ap;
	char *ptr = NULL;
	int debuglevel = 0;
	int ret;

	switch (level) {
	case TDB_DEBUG_FATAL:
		debuglevel = 0;
		break;
	case TDB_DEBUG_ERROR:
		debuglevel = 1;
		break;
	case TDB_DEBUG_WARNING:
		debuglevel = 2;
		break;
	case TDB_DEBUG_TRACE:
		debuglevel = 5;
		break;
	default:
		debuglevel = 0;
	}

	va_start(ap, format);
	ret = vasprintf(&ptr, format, ap);
	va_end(ap);

	if (ret != -1) {
		const char *name = tdb_name(tdb);
		DEBUG(debuglevel, ("tdb(%s): %s", name ? name : "unnamed", ptr));
		free(ptr);
	}
}

struct tdb_wrap_private {
	struct tdb_context *tdb;
	const char *name;
	struct tdb_wrap_private *next, *prev;
};

static int failed;

static int copy_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
        TDB_CONTEXT *tdb_new = (TDB_CONTEXT *)state;

        if (tdb_store(tdb_new, key, dbuf, TDB_INSERT) != 0) {
                DEBUG(1,("TRIMTDB:Failed to insert into %s\n", tdb_name(tdb_new)));
                failed = 1;
                return 1;
        }
        return 0;
}

static int dummy_fn(TDB_CONTEXT *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
        return 0;
}

static char *add_suffix(const char *name, const char *suffix)
{
        char *ret;
        int len = strlen(name) + strlen(suffix) + 1;
        ret = (char *)malloc(len);
        if (!ret) {
                DEBUG(1,("TRIMTDB:Out of memory!\n"));
                exit(1);
        }
        snprintf(ret, len, "%s%s", name, suffix);
        return ret;
}


static struct tdb_wrap_private *tdb_list;

/* destroy the last connection to a tdb */
static int tdb_wrap_private_destructor(struct tdb_wrap_private *w)
{
	tdb_close(w->tdb);
	DLIST_REMOVE(tdb_list, w);
	return 0;
}

static struct tdb_wrap_private *tdb_wrap_private_open(TALLOC_CTX *mem_ctx,
						      const char *name,
						      int hash_size,
						      int tdb_flags,
						      int open_flags,
						      mode_t mode)
{
    struct tdb_wrap_private *result;
    struct tdb_logging_context lctx = { .log_fn = tdb_wrap_log };
    TDB_CONTEXT *tdb;
    TDB_CONTEXT *tdb_new;
    char *tmp_name;
    int count1, count2;
    struct stat sto, stn;
    uint32_t TenMB = 10*1024*1024;

    result = talloc_pooled_object(mem_ctx, struct tdb_wrap_private,
                    1, strlen(name)+1);
    if (result == NULL) {
        return NULL;
    }
    /* Doesn't fail, see talloc_pooled_object */
    result->name = talloc_strdup(result, name);

    result->tdb = tdb_open_ex(name, hash_size, tdb_flags,
                    open_flags, mode, &lctx, NULL);
    if (result->tdb == NULL) {
        goto fail;
    }
    tdb = result->tdb;
    if ( (stat(name, &sto) == 0) && (sto.st_size > TenMB) && \
                    ((tdb_flags & TDB_TRIM_SIZE) == TDB_TRIM_SIZE) ) {
        tmp_name = add_suffix(name, ".tmp");
        unlink(tmp_name);
        tdb_new = tdb_open_ex(tmp_name,
                hash_size,
                tdb_flags|TDB_NOMMAP,
                open_flags, mode,
                &lctx, NULL);
        if (!tdb_new) {
            DEBUG(1,("TDBTRIM:Unable to open file %s\n",tmp_name));
            free(tmp_name);
            goto cont;
        }
        if (tdb_transaction_start(tdb) != 0) {
            DEBUG(1,("TDBTRIM:Failed to start transaction on original tdb\n"));
            tdb_close(tdb_new);
            unlink(tmp_name);
            free(tmp_name);
            goto cont;
        }
        /* lock the backup tdb so that nobody else can change it */
        if (tdb_lockall(tdb_new) != 0) {
            DEBUG(1,("TDBTRIM:Failed to lock backup tdb\n"));
            tdb_close(tdb_new);
            unlink(tmp_name);
            free(tmp_name);
            if (tdb_transaction_cancel(tdb) != 0 ) goto fail;
            goto cont;
		}

        failed = 0;

        /* traverse and copy */
        count1 = tdb_traverse(tdb, copy_fn, (void *)tdb_new);
        if (count1 < 0 || failed) {
            DEBUG(1,("TDBTRIM:failed to copy %s\n", name));
            tdb_close(tdb_new);
            unlink(tmp_name);
            free(tmp_name);
            if (tdb_transaction_cancel(tdb) != 0 ) goto fail;
            goto cont;
        }

        /* copy done, unlock the backup tdb */
        tdb_unlockall(tdb_new);

#ifdef HAVE_FDATASYNC
        if (fdatasync(tdb_fd(tdb_new)) != 0)
#else
        if (fsync(tdb_fd(tdb_new)) != 0)
#endif
        {
            /* not fatal */
            DEBUG(1,("TDBTRIM:failed to fsync backup file\n"));
        }

        /* close the new tdb and re-open read-only */
        tdb_close(tdb_new);
        tdb_new = tdb_open_ex(tmp_name,
                0,
                tdb_flags|TDB_NOMMAP,
                O_RDONLY, 0,
                &lctx, NULL);

        if (!tdb_new) {
            DEBUG(1,("TDBTRIM:failed to reopen %s\n", tmp_name));
            unlink(tmp_name);
            free(tmp_name);
            if (tdb_transaction_cancel(tdb) != 0 ) goto fail;
            goto cont;
        }
        /* traverse the new tdb to confirm */
        count2 = tdb_traverse(tdb_new, dummy_fn, NULL);
        if (count2 != count1) {
            DEBUG(1,("TDBTRIM:failed to copy %s\n", name));
            tdb_close(tdb_new);
            unlink(tmp_name);
            free(tmp_name);
            if (tdb_transaction_cancel(tdb) != 0 ) goto fail;
            goto cont;
        }

        if ((stat(name, &sto) == 0) && (stat(tmp_name, &stn) == 0) && ( stn.st_size < sto.st_size)) {
            DEBUG(1,("TDBTRIM: tdb %s before trim = %u, after trim = %u\n",name,(uint32_t)sto.st_size,(uint32_t)stn.st_size));
            /* close the new tdb and rename it to original file */
            tdb_close(tdb_new);
            tdb_close(tdb);

            if (rename(tmp_name, name) != 0) {
                DEBUG(1,("TDBTRIM:failed to copy %s\n", name));
                free(tmp_name);
                goto fail; /* unexpected, fail */
            }

            free(tmp_name);

            /* Now reopen the trimmed tdb file! */
            result->tdb = tdb_open_ex(name, hash_size, tdb_flags,
                open_flags, mode, &lctx, NULL);
            if (result->tdb == NULL) {
                goto fail;
            }
        } else {
            DEBUG(1,("TDBTRIM: tdb %s old size = %u, new size = %u, not trimming\n",name,(uint32_t)sto.st_size,(uint32_t)stn.st_size));
            tdb_close(tdb_new);
            unlink(tmp_name);
            free(tmp_name);
            if (tdb_transaction_cancel(tdb) != 0 ) goto fail;
            goto cont;
        }
    }
cont:
    talloc_set_destructor(result, tdb_wrap_private_destructor);
    DLIST_ADD(tdb_list, result);
    return result;

fail:
    TALLOC_FREE(result);
    return NULL;
}

/*
  wrapped connection to a tdb database
  to close just talloc_free() the tdb_wrap pointer
 */
struct tdb_wrap *tdb_wrap_open(TALLOC_CTX *mem_ctx,
			       const char *name, int hash_size, int tdb_flags,
			       int open_flags, mode_t mode)
{
	struct tdb_wrap *result;
	struct tdb_wrap_private *w;

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	result = talloc(mem_ctx, struct tdb_wrap);
	if (result == NULL) {
		return NULL;
	}

	for (w=tdb_list;w;w=w->next) {
		if (strcmp(name, w->name) == 0) {
			break;
		}
	}

	if (w == NULL) {

		if (tdb_flags & TDB_MUTEX_LOCKING) {
			if (!tdb_runtime_check_for_robust_mutexes()) {
				tdb_flags &= ~TDB_MUTEX_LOCKING;
			}
		}

		w = tdb_wrap_private_open(result, name, hash_size, tdb_flags,
					  open_flags, mode);
	} else {
		/*
		 * Correctly use talloc_reference: The tdb will be
		 * closed when "w" is being freed. The caller never
		 * sees "w", so an incorrect use of talloc_free(w)
		 * instead of calling talloc_unlink is not possible.
		 * To avoid having to refcount ourselves, "w" will
		 * have multiple parents that hang off all the
		 * tdb_wrap's being returned from here. Those parents
		 * can be freed without problem.
		 */
		if (talloc_reference(result, w) == NULL) {
			goto fail;
		}
	}
	if (w == NULL) {
		goto fail;
	}
	result->tdb = w->tdb;
	return result;
fail:
	TALLOC_FREE(result);
	return NULL;
}
