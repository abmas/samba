/*
   Unix SMB/CIFS implementation.
   Main SMB server routines
   Copyright (C) Andrew Tridgell		1992-1998
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002-2003
   Copyright (C) Volker Lendecke		1993-2007
   Copyright (C) Jeremy Allison			1993-2007

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "nt_printing.h"
#include "printing/pcap.h"
#include "printing/load.h"
#include "auth.h"
#include "messages.h"
#include "lib/param/loadparm.h"
#include "../lib/tsocket/tsocket.h"

struct smbd_open_socket;
struct smbd_child_pid;

struct smbd_parent_context {
        bool interactive;

        struct tevent_context *ev_ctx;
        struct messaging_context *msg_ctx;

        /* the list of listening sockets */
        struct smbd_open_socket *sockets;

        /* the list of current child processes */
        struct smbd_child_pid *children;
        size_t num_children;

        struct server_id cleanupd;

        struct tevent_timer *cleanup_te;
};

struct smbd_open_socket {
        struct smbd_open_socket *prev, *next;
        struct smbd_parent_context *parent;
        int fd;
        struct tevent_fd *fde;
};

struct smbd_child_pid {
        struct smbd_child_pid *prev, *next;
        pid_t pid;
};

/*
 * The persistent pcap cache is populated by the background print process. Per
 * client smbds should only reload their printer share inventories if this
 * information has changed. Use reload_last_pcap_time to detect this.
 */
static time_t reload_last_pcap_time = 0;

bool snum_is_shared_printer(int snum)
{
	return (lp_browseable(snum) && lp_snum_ok(snum) && lp_printable(snum));
}

/**
 * @brief Purge stale printer shares and reload from pre-populated pcap cache.
 *
 * This function should normally only be called as a callback on a successful
 * pcap_cache_reload(), or on client enumeration.
 *
 * @param[in] ev        The event context.
 *
 * @param[in] msg_ctx   The messaging context.
 */
void delete_and_reload_printers(struct tevent_context *ev,
				struct messaging_context *msg_ctx)
{
	int n_services;
	int pnum;
	int snum;
	const char *pname;
	bool ok;
	time_t pcap_last_update;
	TALLOC_CTX *frame = talloc_stackframe();

	ok = pcap_cache_loaded(&pcap_last_update);
	if (!ok) {
		DEBUG(1, ("pcap cache not loaded\n"));
		talloc_free(frame);
		return;
	}

	if (reload_last_pcap_time == pcap_last_update) {
		DEBUG(5, ("skipping printer reload, already up to date.\n"));
		talloc_free(frame);
		return;
	}
	reload_last_pcap_time = pcap_last_update;

	/* Get pcap printers updated */
	load_printers(ev, msg_ctx);

	n_services = lp_numservices();
	pnum = lp_servicenumber(PRINTERS_NAME);

	DEBUG(10, ("reloading printer services from pcap cache\n"));

	/*
	 * Add default config for printers added to smb.conf file and remove
	 * stale printers
	 */
	for (snum = 0; snum < n_services; snum++) {
		/* avoid removing PRINTERS_NAME */
		if (snum == pnum) {
			continue;
		}

		/* skip no-printer services */
		if (!snum_is_shared_printer(snum)) {
			continue;
		}

		pname = lp_printername(frame, snum);

		/* check printer, but avoid removing non-autoloaded printers */
		if (lp_autoloaded(snum) && !pcap_printername_ok(pname)) {
			lp_killservice(snum);
		}
	}

	/* Make sure deleted printers are gone */
	load_printers(ev, msg_ctx);

	talloc_free(frame);
}

/****************************************************************************
 Reload the services file.
**************************************************************************/
extern void reset_tmp_svtfs_lockdir_storageip(void);

bool reload_services(struct smbd_server_connection *sconn,
		     bool (*snumused) (struct smbd_server_connection *, int),
		     bool test)
{
	struct smbXsrv_connection *xconn = NULL;
	bool ret;

	if (lp_loaded()) {
		char *fname = lp_next_configfile(talloc_tos());
		if (file_exist(fname) &&
		    !strcsequal(fname, get_dyn_CONFIGFILE())) {
			set_dyn_CONFIGFILE(fname);
			test = False;
		}
		TALLOC_FREE(fname);
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return(True);

	lp_killunused(sconn, snumused);

	reset_tmp_svtfs_lockdir_storageip();

	ret = lp_load_with_shares(get_dyn_CONFIGFILE());

	/* perhaps the config filename is now set */
	if (!test) {
		reload_services(sconn, snumused, true);
	}

	reopen_logs();

	load_interfaces();

	if (sconn != NULL && sconn->client != NULL) {
		xconn = sconn->client->connections;
	}
	for (;xconn != NULL; xconn = xconn->next) {
		set_socket_options(xconn->transport.sock, "SO_KEEPALIVE");
		set_socket_options(xconn->transport.sock, lp_socket_options());
	}

	mangle_reset_cache();
	reset_stat_cache();

	/* this forces service parameters to be flushed */
	set_current_service(NULL,0,True);

	return(ret);
}

extern void closedb_for_index( struct db_context **, int);
extern void get_removed_svtfs_lockdir_storageip_indices (int * indexArray);
extern struct db_context * brlock_db[], * leases_db[], * lock_db[], * smbXsrv_client_global_db_ctx[], * smbXsrv_open_global_db_ctx[], * smbXsrv_tcon_global_db_ctx[], * smbXsrv_session_global_db_ctx[], * smbXsrv_version_global_db_ctx[];
#define MAX_LOCKDIRS 32
extern char * svtfs_storage_ip[];
extern char * svtfs_lockdir_path[];

void close_socket(char *storage_ip_address, struct smbd_parent_context *parent);

void closedbs_not_owned(struct smbd_server_connection * sconn,
                        struct smbd_parent_context * parent)
{
        int indexArray[MAX_LOCKDIRS], i, j;
        char * storip = NULL;

        DEBUG(1, ("closedbs_not_owned: entering\n"));
        if (sconn) {
                DEBUG(1, ("closedbs_not_owned: we have an sconn\n"));
                if (tsocket_address_is_inet(sconn->local_address, "ip")) {
                        storip = tsocket_address_inet_addr_string( sconn->local_address, talloc_tos());
                        DEBUG(1, ("closedbs_not_owned: storage_ip for this connection = %s\n", storip));
                }
        }

        for (i=0; i < MAX_LOCKDIRS; i++) indexArray[i]=-1;
        get_removed_svtfs_lockdir_storageip_indices(&indexArray[0]);
        for (i=0; i < MAX_LOCKDIRS; i++)
        {
                j = indexArray[i];
                if (j == -1) continue;
                DEBUG(1, ("closedbs_not_owned: in loop, working on index %s\n", svtfs_storage_ip[j]));
                if (storip) {
                        DEBUG(1, ("closedbs_not_owned: storage_ip for this connection = %s, storeip for index = %s\n", storip,svtfs_storage_ip[j]));
                        /*exit_server_cleanly("svtfs: Exiting because the storage IP is gone!");*/
                        if (strcmp(svtfs_storage_ip[j],storip) == 0) {
                             exit(0);
                        }
                }
                closedb_for_index (brlock_db, j);
                closedb_for_index (leases_db, j);
                closedb_for_index (lock_db, j);
                closedb_for_index (smbXsrv_client_global_db_ctx, j);
                closedb_for_index (smbXsrv_open_global_db_ctx, j);
                closedb_for_index (smbXsrv_tcon_global_db_ctx, j);
                closedb_for_index (smbXsrv_session_global_db_ctx, j);
                closedb_for_index (smbXsrv_version_global_db_ctx, j);
                if (svtfs_lockdir_path[j] != NULL) {
                        talloc_free(svtfs_lockdir_path[j]);
                        svtfs_lockdir_path[j]=NULL;
                }
                if (svtfs_storage_ip[j] != NULL) {
                        DEBUG(1, ("closedbs_not_owned: in loop, removing %s\n", svtfs_storage_ip[j]));
                        if (parent) {
                              DEBUG(1, ("closedbs_not_owned: in loop, closing socket %s\n", svtfs_storage_ip[j]));
                              close_socket(svtfs_storage_ip[j], parent);
                        }
                        talloc_free(svtfs_storage_ip[j]);
                        svtfs_storage_ip[j]=NULL;
                }
        }
}

void close_socket(char *storage_ip_address, struct smbd_parent_context *parent)
{
        struct tsocket_address *local_address = NULL;
        struct sockaddr_storage ss_srv;
        void *sp_srv = (void *)&ss_srv;
        struct sockaddr *sa_srv = (struct sockaddr *)sp_srv;
        struct smbd_open_socket *socket, *next_socket;
        socklen_t sa_socklen = sizeof(ss_srv);
        int ret;

        /*
         *  Find the socket associated with this storage IP address
         */
        DEBUG(1, ("close_socket: closing socket %s\n", storage_ip_address));
        socket = parent->sockets;

        while ( socket != NULL ) {

                next_socket = socket->next;

                ret = getsockname(socket->fd, sa_srv, &sa_socklen);
                if (ret != 0) {
                        int saved_errno = errno;
                        int level = (errno == ENOTCONN)?2:0;
                        DEBUG(level,("getsockname() failed - %s\n",
                              strerror(saved_errno)));
                        return;
                }
                ret = tsocket_address_bsd_from_sockaddr(parent,
                                                sa_srv, sa_socklen,
                                                &local_address);
                if (ret != 0) {
                        int saved_errno = errno;
                        DEBUG(0,("%s: tsocket_address_bsd_from_sockaddr remote failed - %s\n",
                                __location__, strerror(saved_errno)));
                        return;
                }

                DEBUG(1, ("close_socket: compare to %s\n", tsocket_address_string(local_address, talloc_tos())));
                if ( strcmp(storage_ip_address, tsocket_address_inet_addr_string(local_address, talloc_tos())) == 0 ) {
                        DEBUG(1, ("close_socket: closing fd for address %s\n", storage_ip_address));
                        talloc_free(socket->fde);
                        DLIST_REMOVE(parent->sockets, socket);
                        close(socket->fd);
                        talloc_free(socket);
                }

                socket = next_socket;
        }
}

