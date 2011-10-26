/* derived from openflow reference controller
 * provide a library to add and remove layer 3 rules
 */

#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "config.h"
#include "command-line.h"
#include "daemon.h"
#include "learning-switch.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "rconn.h"
#include "timeval.h"
#include "vconn.h"
#include "vlog-socket.h"
#include "vlog.h"
#include "flow.h"
#include "stp.h"
#include "controller.h"
#include "ctrl_table.h"
#include "vconn-provider.h"

#ifdef HAVE_OPENSSL
#include "vconn-ssl.h"
#endif

#define THIS_MODULE VLM_controller
#define MAX_SWITCHES 16
#define MAX_LISTENERS 16

struct switch_ {
    struct lswitch *lswitch;
    struct rconn *rconn;
    struct ctrl_table *ctp;
};

/* lswitch is originally defined in learning switch library, move here for compiling */
struct lswitch {
    /* If nonnegative, the switch sets up flows that expire after the given
     * number of seconds (or never expire, if the value is OFP_FLOW_PERMANENT).
     * Otherwise, the switch processes every packet. */
    int max_idle;

    unsigned long long int datapath_id;
    uint32_t capabilities;
    time_t last_features_request;
    struct mac_learning *ml;    /* NULL to act as hub instead of switch. */

    /* Number of outgoing queued packets on the rconn. */
    int n_queued;

    /* Spanning tree protocol implementation.
     *
     * We implement STP states by, whenever a port's STP state changes,
     * querying all the flows on the switch and then deleting any of them that
     * are inappropriate for a port's STP state. */
    long long int next_query;   /* Next time at which to query all flows. */
    long long int last_query;   /* Last time we sent a query. */
    long long int last_reply;   /* Last time we received a query reply. */
    unsigned int port_states[STP_MAX_PORTS];
    uint32_t query_xid;         /* XID used for query. */
    int n_flows, n_no_recv, n_no_send;
};

/* the structure storing layer 3 flow entries to be added/removed */
struct l3_entry {
    bool valid;
    char * ip_src;
    char * ip_dst;
    uint32_t ip_src_mask;
    uint32_t ip_dst_mask;
    uint16_t duration;
};

/* Learn the ports on which MAC addresses appear? */
static bool learn_macs = true;

/* Set up flows?  (If not, every packet is processed at the controller.) */
static bool setup_flows = true;

/* --max-idle: Maximum idle time, in seconds, before flows expire. */
static int max_idle = 60;

struct l3_entry new_entry = {false, NULL, NULL, 0, 0, 0};
struct l3_entry del_entry = {false, NULL, NULL, 0, 0, 0};
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
static struct switch_ switches[MAX_SWITCHES];
static struct pvconn *listeners[MAX_LISTENERS];
static int n_switches, n_listeners;
pthread_t pth;

static int do_switching(struct switch_ *);
static void new_switch(struct switch_ *, struct vconn *, const char *name);
static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

static void actual_add(struct switch_ *);
static void actual_remove(struct switch_ *);
static void queue_tx(struct lswitch *, struct rconn *, struct ofpbuf *);

void wait_for_switch() {
  while (!n_switches) sleep(1);
}

void
controller_init(int argc, char *argv[])
{
    int retval;
    int i;

    set_program_name(argv[0]);
    //register_fault_handlers(); CANNOT LINK TO THE OPENFLOW LIBRARY
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);

    if (argc - optind < 1) {
        ofp_fatal(0, "at least one vconn argument required; "
                  "use --help for usage");
    }
    n_switches = n_listeners = 0;
    for (i = optind; i < argc; i++) {
        const char *name = argv[i];
        struct vconn *vconn;
        int retval;

        retval = vconn_open(name, OFP_VERSION, &vconn);
        if (!retval) {
            if (n_switches >= MAX_SWITCHES) {
                ofp_fatal(0, "max %d switch connections", n_switches);
            }
            new_switch(&switches[n_switches++], vconn, name);
            continue;
        } else if (retval == EAFNOSUPPORT) {
            struct pvconn *pvconn;
            retval = pvconn_open(name, &pvconn);
            if (!retval) {
                if (n_listeners >= MAX_LISTENERS) {
                    ofp_fatal(0, "max %d passive connections", n_listeners);
                }
                listeners[n_listeners++] = pvconn;
            }
        }
        if (retval) {
            VLOG_ERR("%s: connect: %s", name, strerror(retval));
        }
    }
    if (n_switches == 0 && n_listeners == 0) {
        ofp_fatal(0, "no active or passive switch connections");
    }

    //die_if_already_running();
    //daemonize();

    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        ofp_fatal(retval, "Could not listen for vlog connections");
    }
}

void *
controller_loop(void *ptr)
{
    while (n_switches > 0 || n_listeners > 0) {
        int iteration;
        int i;

        /* Accept connections on listening vconns. */
        for (i = 0; i < n_listeners && n_switches < MAX_SWITCHES; ) {
	  struct sockaddr_in saddr;
            struct vconn *new_vconn;
            int retval;

            retval = pvconn_accept(listeners[i], OFP_VERSION, &new_vconn);
            if (!retval || retval == EAGAIN) {
                if (!retval) {
                    new_switch(&switches[n_switches++], new_vconn, "tcp");
		    saddr.sin_addr.s_addr = new_vconn->ip;
		    printf("new switch connected: %s\n", inet_ntoa(saddr.sin_addr));
                }
                i++;
            } else {
                pvconn_close(listeners[i]);
                listeners[i] = listeners[--n_listeners];
            }
        }

        /* Do some switching work.  Limit the number of iterations so that
         * callbacks registered with the poll loop don't starve. */
        for (iteration = 0; iteration < 50; iteration++) {
            bool progress = false;
            for (i = 0; i < n_switches; ) {
                struct switch_ *this = &switches[i];//if(isempty(this->ctp)) printf("switch %d empty\n", i); else printf("switch %d NOT empty\n", i);
                int retval = do_switching(this);
                if (!retval || retval == EAGAIN) {
                    if (!retval) {
                        progress = true;
                    }
                    i++;
                } else {
                    rconn_destroy(this->rconn);
                    lswitch_destroy(this->lswitch);
                    switches[i] = switches[--n_switches];
                }
            }
            if (!progress) {
                break;
            }
        }
        for (i = 0; i < n_switches; i++) {
            struct switch_ *this = &switches[i];
            lswitch_run(this->lswitch, this->rconn);
        }

        /* Wait for something to happen. */
        if (n_switches < MAX_SWITCHES) {
            for (i = 0; i < n_listeners; i++) {
                pvconn_wait(listeners[i]);
            }
        }
        for (i = 0; i < n_switches; i++) {
            struct switch_ *sw = &switches[i];
            rconn_run_wait(sw->rconn);
            rconn_recv_wait(sw->rconn);
            lswitch_wait(sw->lswitch);
        }
        poll_block();
    }

    return NULL;
}

void
controller_start()
{
    pthread_create(&pth, NULL, controller_loop, NULL);
}

void
controller_stop()
{
    pthread_cancel(pth);
}

static void
new_switch(struct switch_ *sw, struct vconn *vconn, const char *name)
{
    sw->rconn = rconn_new_from_vconn(name, vconn);
    sw->lswitch = lswitch_create(sw->rconn, learn_macs,
                                 setup_flows ? max_idle : -1);
    sw->ctp = ctrl_table_create();
}

static bool
ctrl_table_process(struct switch_ *sw, struct rconn *rconn, void *opi_)
{
    struct ofp_packet_in *opi = opi_;
    uint16_t in_port = ntohs(opi->in_port);
    //uint16_t out_port = OFPP_FLOOD;

    size_t pkt_ofs, pkt_len;
    struct ofpbuf pkt;
    struct flow flow;

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    pkt.data = opi->data;
    pkt.size = pkt_len;
    flow_extract(&pkt, in_port, &flow);

    if(flow.dl_type != htons(0x0800)) return true; // Let all non-ip packet go through

    //printf("flow.nw_src is %d, flow.nw_dst is %d\n", flow.nw_src, flow.nw_dst);

    // if (ctrl_table_learn(sw->ctp, flow.nw_src, flow.nw_dst, OFPAT_OUTPUT)) {
    /*VLOG_DBG_RL(&rl, "%012llx: learned that "ETH_ADDR_FMT" is on "
      "port %"PRIu16, sw->datapath_id,
      ETH_ADDR_ARGS(flow.dl_src), in_port);*/
    //    }
    //if(OFPAT_OUTPUT == ctrl_table_lookup(sw->ctp, 33554442, 50331658)) printf("found it!\n");

    enum ofp_action_type learned_action = ctrl_table_lookup(sw->ctp, flow.nw_src, flow.nw_dst);
    if (learned_action == OFPAT_OUTPUT) return true;
    else return false;
}

static int
do_switching(struct switch_ *sw)
{
    unsigned int packets_sent;
    struct ofpbuf *msg;

    packets_sent = rconn_packets_sent(sw->rconn);

    msg = rconn_recv(sw->rconn);
    if (msg) {
        if(ctrl_table_process(sw, sw->rconn, msg->data)) {
            lswitch_process_packet(sw->lswitch, sw->rconn, msg);
        } else {
	  // in this case, the controller ignore the packet
	  //printf("packet dropped\n");
        }
        ofpbuf_delete(msg);
    }

    if(del_entry.valid == true && rconn_is_connected(sw->rconn))
        actual_remove(sw);

    rconn_run(sw->rconn);

    return (!rconn_is_alive(sw->rconn) ? EOF
            : rconn_packets_sent(sw->rconn) != packets_sent ? 0
            : EAGAIN);
}

static void
queue_tx(struct lswitch *sw, struct rconn *rconn, struct ofpbuf *b)
{
    int retval = rconn_send_with_limit(rconn, b, &sw->n_queued, 10);
    if (retval && retval != ENOTCONN) {
        if (retval == EAGAIN) {
            VLOG_INFO_RL(&rl, "%012llx: %s: tx queue overflow",
                         sw->datapath_id, rconn_get_name(rconn));
        } else {
            VLOG_WARN_RL(&rl, "%012llx: %s: send: %s",
                         sw->datapath_id, rconn_get_name(rconn),
                         strerror(retval));
        }
    }
}



static void
actual_remove(struct switch_ *sw)
{
    struct flow flow = {
        inet_addr(del_entry.ip_src),	// uint32_t IP source address.
        inet_addr(del_entry.ip_dst),	// uint32_t IP destination address.
        0,				// uint16_t Input switch port.
        0,				// uint16_t Input VLAN id.
        htons(0x0800),			// uint16_t Ethernet frame type.
        0,				// uint16_t TCP/UDP source port.
        0,				// uint16_t TCP/UDP destination port.
        {0,0,0,0,0,0},			// uint8_t Ethernet source address.
        {0,0,0,0,0,0},			// uint8_t Ethernet destination address.
        0,				// uint8_t Input VLAN priority.
        0,				// uint8_t IPv4 DSCP.
        0,				// uint8_t IP protocol.
        {0,0,0}				// uint8_t
    };
    struct ofpbuf *temp;
    struct ofp_flow_mod *ofm;

    temp = make_del_flow(&flow);
    ofm = temp->data;

    //ofm->match.wildcards = htonl(OFPFW_ALL);

    ofm->match.wildcards = htonl(OFPFW_IN_PORT |
				 OFPFW_DL_VLAN |
				 OFPFW_DL_SRC |
				 OFPFW_DL_DST |
				 //OFPFW_DL_TYPE |
                                 OFPFW_NW_PROTO |
				 OFPFW_TP_SRC |
				 OFPFW_TP_DST |
				 //OFPFW_NW_SRC_ALL |
				 //OFPFW_NW_DST_ALL |
				 OFPFW_DL_VLAN_PCP |
				 OFPFW_NW_TOS);

    //ofm->priority = htons(65535);
    ofm->command = htons(OFPFC_DELETE);
    //ofm->hard_timeout = htons(100);
    //ofm->buffer_id = htonl(-1);

    queue_tx(sw->lswitch, sw->rconn, temp);

    del_entry.ip_src = NULL;
    del_entry.ip_dst = NULL;
    del_entry.ip_src_mask = 0;
    del_entry.ip_dst_mask = 0;
    del_entry.duration = 0;
    del_entry.valid = false;

    //printf("flow removed\n");
}

void
of_add_l3_rule(char *ip_src, char *ip_dst, uint32_t ip_src_mask, uint32_t ip_dst_mask, uint16_t duration)
{
    /*new_entry.ip_src = ip_src;
    new_entry.ip_dst = ip_dst;
    new_entry.ip_src_mask = ip_src_mask;
    new_entry.ip_dst_mask = ip_dst_mask;
    new_entry.duration = duration;
    new_entry.valid = true;*/

    int i;
    for (i = 0; i < n_switches; i++) {
        struct switch_ *this = &switches[i];
	//printf("before learning\n");if(isempty(this->ctp)) printf("switch %d is empty\n", i); else printf("switch %d is NOT empty\n", i);
        ctrl_table_learn(this->ctp, inet_addr(ip_src), inet_addr(ip_dst), OFPAT_OUTPUT);
        ctrl_table_learn(this->ctp, inet_addr(ip_dst), inet_addr(ip_src), OFPAT_OUTPUT);
	//printf("after learning\n");if(isempty(this->ctp)) printf("switch %d is empty\n", i); else printf("switch %d is NOT empty\n", i);
    }
}

void
of_remove_l3_rule(char *ip_src, char *ip_dst, uint32_t ip_src_mask, uint32_t ip_dst_mask)
{

  int i;
  for (i = 0; i < n_switches; i++) {
    struct switch_ *this = &switches[i];
    ctrl_table_flush(this->ctp);
  }

  del_entry.ip_src = ip_src;
  del_entry.ip_dst = ip_dst;
  del_entry.ip_src_mask = ip_src_mask;
  del_entry.ip_dst_mask = ip_dst_mask;
  del_entry.valid = true;

}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_MAX_IDLE = UCHAR_MAX + 1,
        OPT_PEER_CA_CERT,
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"hub",         no_argument, 0, 'H'},
        {"noflow",      no_argument, 0, 'n'},
        {"max-idle",    required_argument, 0, OPT_MAX_IDLE},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        VCONN_SSL_LONG_OPTIONS
        {"peer-ca-cert", required_argument, 0, OPT_PEER_CA_CERT},
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int indexptr;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, &indexptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'H':
            learn_macs = false;
            break;

        case 'n':
            setup_flows = false;
            break;

        case OPT_MAX_IDLE:
            if (!strcmp(optarg, "permanent")) {
                max_idle = OFP_FLOW_PERMANENT;
            } else {
                max_idle = atoi(optarg);
                if (max_idle < 1 || max_idle > 65535) {
                    ofp_fatal(0, "--max-idle argument must be between 1 and "
                              "65535 or the word 'permanent'");
                }
            }
            break;

        case 'h':
            usage();

        case 'V':
            printf("%s "VERSION" compiled "__DATE__" "__TIME__"\n", argv[0]);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

#ifdef HAVE_OPENSSL
        VCONN_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            vconn_ssl_set_peer_ca_cert_file(optarg);
            break;
#endif

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: OpenFlow controller\n"
           "usage: %s [OPTIONS] METHOD\n"
           "where METHOD is any OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, true, false);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -H, --hub               act as hub instead of learning switch\n"
           "  -n, --noflow            pass traffic, but don't add flows\n"
           "  --max-idle=SECS         max idle time for new flows\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
