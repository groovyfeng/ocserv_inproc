/*
 * Copyright (C) 2023 Microsoft Corporation
 *
 * Author: Russ Young
 *
 * This file is part of ocserv.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */#include <config.h>
#include <system.h>
#include <main.h>
#include <worker.h>
#include <sched.h>
#include "setproctitle.h"

typedef struct worker_list_st
{
    struct list_head head;
    unsigned int total;
} worker_list_st;

typedef struct worker_node_st
{
    /* The worker_st must be first */
    struct worker_st ws;
    struct list_node list;
} worker_node_st;

typedef struct worker_connection_st
{
    ev_io connection_watcher;
    struct ev_loop *loop;
    int fd;
    struct main_server_st *s;
    int worker_index;
    worker_list_st worker_list;
} worker_connection_st;

worker_connection_st wcs;
extern struct ev_loop *worker_loop;
extern int worker_argc;
extern char **worker_argv;
extern ev_signal term_sig_watcher;
extern ev_signal int_sig_watcher;
extern ev_signal alarm_sig_watcher;
extern ev_signal reload_sig_watcher;


void vpn_accept_connection(struct worker_st *ws);
int receive_connection_from_main(main_server_st *s, int socket, worker_st *ws);
int worker_st_destructor(worker_st *ws);
static void term_sig_watcher_cb(EV_P_ ev_signal *w, int revents);
static void reload_sig_watcher_cb(EV_P_ ev_signal *w, int revents);
void cstp_send_terminate(struct worker_st *ws);

static void set_affinity(int cpu)
{
    cpu_set_t cpu_set;        /* Define your cpu_set bit mask. */
    CPU_ZERO(&cpu_set);       /* Initialize it all to 0, i.e. no CPUs selected. */
    CPU_SET(cpu, &cpu_set);     /* set the bit that represents core 7. */
    sched_setaffinity(0, sizeof(cpu_set), &cpu_set); /* Set affinity of this process to */
}

void new_connection_cb(EV_P_ ev_io *w, int revents)
{
    worker_connection_st *wcs = (worker_connection_st *)w;
    main_server_st *s = wcs->s;
    worker_node_st* worker_node = talloc_zero(s, worker_node_st);
    if (worker_node == NULL) {
        syslog(LOG_ERR, "Failed to allocate memory for client worker\n");
        return;
    }
    struct worker_st* ws = &worker_node->ws;
    list_add_tail(&wcs->worker_list.head, &worker_node->list);
    wcs->worker_list.total ++;

    int index = ((worker_connection_st *)w)->worker_index;
    init_worker_st(s, ws, -1, index, ws->conn_fd, 0);
    talloc_set_destructor(ws, worker_st_destructor);

    oclog(ws, LOG_INFO, "worker received new client connection\n");

    int fd = receive_connection_from_main(s, w->fd, ws);
    if (fd < 0) {
        oclog(ws, LOG_ERR, "Failed to receive fd from main\n");
        return;
    }
    oclog(ws, LOG_INFO, "worker received connection (fd = %d)\n", fd);
    oclog(ws, LOG_DEBUG, "worker secmod_addr_path: %s %d", ws->secmod_addr.sun_path, ws->secmod_addr_len);

    vpn_accept_connection(ws);
}

int run_worker_proc(main_server_st *s, int index)
{
    int ipc[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, ipc);
    if (ret < 0)
    {
        mslog(s, NULL, LOG_ERR, "Error creating socket pair for worker");
        return (-1);
    }
    int server_fd = ipc[0];
    int client_fd = ipc[1];
    mslog(s, NULL, LOG_DEBUG, "Created socket pair for worker");

    pid_t wPid = fork();
    if (wPid == 0)
    {
        // we are the client.
        /* main pool */
        s->main_pool = talloc_init("main");
        if (s->main_pool == NULL) {
            fprintf(stderr, "talloc init error\n");
            exit(EXIT_FAILURE);
        }

        s->config_pool = talloc_init("config");
        if (s->config_pool == NULL) {
            fprintf(stderr, "talloc init error\n");
            exit(EXIT_FAILURE);
        }

        clear_lists(s);
        
        s->stats.start_time = s->stats.last_reset = time(NULL);
        s->top_fd = -1;
        s->ctl_fd = -1;

        close(server_fd);

        init_worker_st(s, s->ws, -1, -1, -1, 0);
        worker_st* ws = s->ws;

        restore_secmod_socket_file_name(s->sec_mod_instances[index].secmod_addr.sun_path);
        /* Initialize GnuTLS */
        tls_global_init();
        oclog(ws, LOG_INFO, "sec-mod path %s\n", s->sec_mod_instances[index].secmod_addr.sun_path);

        // getopt processing mutates argv. Create a copy to be parsed.
        char **argv_copy = talloc_zero_array(s->config_pool, char*, worker_argc + 1);
        if (!argv_copy) {
            fprintf(stderr, "memory error\n");
            exit(EXIT_FAILURE);
        }
        for (int i = 0; i < worker_argc; i ++) {
            argv_copy[i] = talloc_strdup(argv_copy, worker_argv[i]);
            if (!argv_copy[i]) {
                fprintf(stderr, "memory error\n");
                exit(EXIT_FAILURE);
            }
        }

        list_head_init(s->vconfig);
        ret = cmd_parser(s->config_pool, worker_argc, argv_copy, s->vconfig, true);
        talloc_free(argv_copy);
        if (ret < 0) {
            fprintf(stderr, "Error in arguments\n");
            exit(EXIT_FAILURE);
        }
        
        set_affinity(index);
        setproctitle("%s-wk-%d", PACKAGE_NAME, index);
        kill_on_parent_kill(SIGTERM);
        oclog(ws, LOG_INFO, "worker started, connect listener fd %d\n", client_fd);
        wcs.fd = client_fd;
	    wcs.loop = EV_DEFAULT;
        wcs.worker_index = index;
        list_head_init(&wcs.worker_list.head);
        ev_set_userdata(wcs.loop, ws);
        worker_loop = wcs.loop;
        wcs.s = s;
        ev_loop_fork(worker_loop);
        ev_init(&alarm_sig_watcher, term_sig_watcher_cb);
    	ev_signal_set (&alarm_sig_watcher, SIGALRM);
	    ev_signal_start (worker_loop, &alarm_sig_watcher);

        ev_init (&int_sig_watcher, term_sig_watcher_cb);
	    ev_signal_set (&int_sig_watcher, SIGINT);
	    ev_signal_start (worker_loop, &int_sig_watcher);

	    ev_init (&term_sig_watcher, term_sig_watcher_cb);
	    ev_signal_set (&term_sig_watcher, SIGTERM);
	    ev_signal_start (worker_loop, &term_sig_watcher);

        ev_init (&reload_sig_watcher, reload_sig_watcher_cb);
        ev_signal_set (&reload_sig_watcher, SIGHUP);
        ev_signal_start (main_loop, &reload_sig_watcher);
	
        ev_io_init(&wcs.connection_watcher, new_connection_cb, client_fd, EV_READ);
        ev_io_start(worker_loop, &wcs.connection_watcher);
        ev_run(worker_loop, 0);
    }
    else if (wPid > 0)
    {
        // we are the server.
        mslog(s, NULL, LOG_INFO, "%d: server forked worker %d\n", getpid(), server_fd);
        close(client_fd);
        worker_mod_instance_st* wmi = &s->worker_mod_instances[index];
        wmi->pid = wPid;
        wmi->is_running = 1;
        wmi->instance = index;
        wmi->cmd_socket = server_fd;
        ev_child_init(&wmi->ev_child, worker_child_watcher_cb, wPid, 0);
        ev_child_start(main_loop, &wmi->ev_child);
    }
    else
    {
        perror("Error forking worker");
        return (-1);
    }
    return 0;
}

static int get_available_worker(main_server_st *s)
{
    int next_worker = -1;
    int active_clients = INT_MAX;
    for (int i = 0; i < s->worker_mod_instance_count; i++) {
        if (s->worker_mod_instances[i].is_running == 0)
            continue;
        if (s->stats.active_clients_per_worker[i] < active_clients || next_worker == -1)
        {
            active_clients = s->stats.active_clients_per_worker[i];
            next_worker = i;
        }
        if (active_clients == 0)
            break;
    }
    return next_worker;
}

int send_connection_to_worker(main_server_st* s, int fd, int cmd_fd, sock_type_t socket_type) // send fd by socket
{
    struct msghdr msg = {0};
    int fds[2] = {fd, cmd_fd};
    char buf[CMSG_SPACE(sizeof(fds))];
    memset(buf, '\0', sizeof(buf));
    xfer_connection_msg message = {.id = xfer_conn_id, .fd_count = 2, .socket_type = socket_type};
    message.remote_addr_len = s->ws->remote_addr_len;
    memcpy(&message.remote_addr, &s->ws->remote_addr, s->ws->remote_addr_len);
    int worker_index = get_available_worker(s);
    if (worker_index < 0)
    {
        mslog(s, NULL, LOG_ERR, "No available workers\n");
        return -1;
    }
    int next_worker = s->worker_mod_instances[worker_index].cmd_socket;

    mslog(s, NULL, LOG_INFO, "sending connection to worker id %d fd %d\n", worker_index, next_worker);

    struct iovec io = {.iov_base = &message, .iov_len = sizeof(message)};

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fds));

    int* fdptr = (int *) CMSG_DATA(cmsg);
    memcpy(fdptr, fds, sizeof(fds));
    // *((int *)CMSG_DATA(cmsg)) = fds;

    msg.msg_controllen = CMSG_SPACE(sizeof(fd));

    if (sendmsg(next_worker, &msg, 0) < 0)
    {
        mslog(s, NULL, LOG_ERR, "%d: Failed to send connection to worker %d\n", getpid(), next_worker);
        perror("Failed to send connection to worker\n");
        return -1;
    }

    return worker_index;
}

int create_workers(main_server_st *s)
{
	mslog(s, NULL, LOG_INFO, "Starting %d instances of ocserv-worker", s->worker_mod_instance_count);

    for (int index = 0; index < s->worker_mod_instance_count; index++)
    {
        int ret = run_worker_proc(s, index);
        if (ret < 0)
        {
            mslog(s, NULL, LOG_ERR, "Error creating worker");
            return (ret);
        }
    }
    return 0;
}

int receive_connection_from_main(main_server_st *s, int socket, worker_st* ws) // receive fd from socket
{
    struct msghdr msg = {0};

    xfer_connection_msg data;
    struct iovec io = {.iov_base = &data, .iov_len = sizeof(data)};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    oclog(ws, LOG_INFO, "receive connection from main\n");

    char c_buffer[256];
    msg.msg_control = c_buffer;
    msg.msg_controllen = sizeof(c_buffer);

    // printf("recvmsg\n");
    int sRcved = recvmsg(socket, &msg, 0);
    if (sRcved <= 0)
    {
        if(errno != EAGAIN && errno != EWOULDBLOCK)
            oclog(ws, LOG_ERR, "Failed to receive message %d\n", errno);
        return sRcved;
    }

    if (msg.msg_iovlen != 1 || io.iov_len != sizeof(data) || data.id != xfer_conn_id || data.fd_count != 2)
    {
        oclog(ws, LOG_ERR, "Failed to receive message bad iov\n");
        return -1;
    }
 
    // printf("Received %d\n", sRcved);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_len != CMSG_LEN(sizeof(int)*2))
    {
        oclog(ws, LOG_ERR, "Failed to receive FDs from main\n");
        return -1;
    }
    int *fds = (int*)CMSG_DATA(cmsg);
    int fd = fds[0];
    ws->cmd_fd = fds[1];
    ws->conn_fd = fd;
    ws->conn_type = data.socket_type;
    ws->remote_addr_len = data.remote_addr_len;
    memcpy(&ws->remote_addr, &data.remote_addr, data.remote_addr_len);
    return fd;
}

void remove_event_watchers(worker_st* ws)
{
    ev_io_stop(worker_loop, &ws->command_watcher);
    ev_io_stop(worker_loop, &ws->tls_watcher);
    ev_io_stop(worker_loop, &DTLS_ACTIVE(ws)->io);
    ev_io_stop(worker_loop, &DTLS_INACTIVE(ws)->io);
    ev_io_stop(worker_loop, &ws->tun_watcher);
    ev_timer_stop(worker_loop, &ws->period_check_watcher);
}

int worker_st_destructor(worker_st * ws)
{
    /* we do not want to cleanup the process, just the worker */
    oclog(ws, LOG_DEBUG, "Exiting worker cleaning up %p", ws);
    worker_node_st *node = (worker_node_st*)ws;
    list_del(&node->list);
    wcs.worker_list.total--;
    NotifyClientDisconnectMsg msg = NOTIFY_CLIENT_DISCONNECT_MSG__INIT;
    send_msg_to_main(ws, CMD_NOTIFY_CLIENT_DISCONNECT, &msg,
			 (pack_size_func) notify_client_disconnect_msg__get_packed_size,
			 (pack_func) notify_client_disconnect_msg__pack);
    /* remove the event watchers for this client*/
    remove_event_watchers(ws);
    /* close open FDs */
    if (ws->cmd_fd != -1) {
        close(ws->cmd_fd);
    }
    cstp_close(ws);
    if (ws->tun_fd != -1) {
        close(ws->tun_fd);
        ws->tun_fd = -1;
    }
    dtls_close(DTLS_ACTIVE(ws));
    dtls_close(DTLS_INACTIVE(ws));
    return 0;
}

static void cleanup_workers()
{
    struct worker_node_st *ltmp = NULL, *lpos;

    if (wcs.worker_list.total == 0)
        return;

    list_for_each_safe(&wcs.worker_list.head, ltmp, lpos, list) {
        cstp_send_terminate(&ltmp->ws);
	}
}

static void term_sig_watcher_cb(EV_P_ ev_signal *w, int revents)
{
    worker_st *ws = ev_userdata(worker_loop);
    oclog(ws, LOG_DEBUG, "Worker received signal %d", w->signum);
    ev_signal_stop(worker_loop, &term_sig_watcher);
    ev_signal_stop(worker_loop, &int_sig_watcher);
    ev_signal_stop(worker_loop, &alarm_sig_watcher);
    cleanup_workers();
    ev_break (worker_loop, EVBREAK_ALL);
    ev_loop_destroy(worker_loop);
    exit(0);
}

static void reload_sig_watcher_cb(EV_P_ ev_signal *w, int revents)
{
    worker_st *ws = ev_userdata(worker_loop);
    main_server_st *s = wcs.s;
    oclog(ws, LOG_INFO, "Reconfiguring worker");
	reload_cfg_file(s->config_pool, s->vconfig, 0);
}