/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <config.h>

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "fault.h"
#include "learning-switch.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "rconn.h"
#include "timeval.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "vlog-socket.h"

#include "vlog.h"
/* modification by Miao, includes */
#include <arpa/inet.h>
#include "flow.h"
#include "stp.h"
#include <time.h>

#define THIS_MODULE VLM_controller
#define MAX_SWITCHES 16
#define MAX_LISTENERS 16

struct switch_ {
    struct lswitch *lswitch;
    struct rconn *rconn;
};

/* Learn the ports on which MAC addresses appear? */
static bool learn_macs = true;

/* Set up flows?  (If not, every packet is processed at the controller.) */
static bool setup_flows = true;

/* --max-idle: Maximum idle time, in seconds, before flows expire. */
static int max_idle = 60;

/* modification by Miao, variables and structures */
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
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
static bool already_added = false;
static long time_taken;
static bool removed = false;

static int do_switching(struct switch_ *);
static void new_switch(struct switch_ *, struct vconn *, const char *name);
static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

/* modification by Miao, functions */
static void of_add_l3_rule(struct switch_ *, char *, char *, uint32_t, uint32_t, uint16_t);
static void of_remove_l3_rule(struct switch_ *, char *);
static void queue_tx(struct lswitch *, struct rconn *, struct ofpbuf *);

int
main(int argc, char *argv[])
{
    struct switch_ switches[MAX_SWITCHES];
    struct pvconn *listeners[MAX_LISTENERS];
    int n_switches, n_listeners;
    int retval;
    int i;

    set_program_name(argv[0]);
    register_fault_handlers();
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

    die_if_already_running();
    daemonize();

    retval = vlog_server_listen(NULL, NULL);
    if (retval) {
        ofp_fatal(retval, "Could not listen for vlog connections");
    }

    while (n_switches > 0 || n_listeners > 0) {
        int iteration;
        int i;

        /* Accept connections on listening vconns. */
        for (i = 0; i < n_listeners && n_switches < MAX_SWITCHES; ) {
            struct vconn *new_vconn;
            int retval;

            retval = pvconn_accept(listeners[i], OFP_VERSION, &new_vconn);
            if (!retval || retval == EAGAIN) {
                if (!retval) {
                    new_switch(&switches[n_switches++], new_vconn, "tcp");
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
                struct switch_ *this = &switches[i];
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

    return 0;
}

static void
new_switch(struct switch_ *sw, struct vconn *vconn, const char *name)
{
    sw->rconn = rconn_new_from_vconn(name, vconn);
    sw->lswitch = lswitch_create(sw->rconn, learn_macs,
                                 setup_flows ? max_idle : -1);
}

static int
do_switching(struct switch_ *sw)
{
    unsigned int packets_sent;
    struct ofpbuf *msg;

    packets_sent = rconn_packets_sent(sw->rconn);

    msg = rconn_recv(sw->rconn);
    if (msg) {
        /*
        size_t pkt_ofs, pkt_len;
        struct ofpbuf pkt;
        struct flow flow;
        struct ofp_packet_in *opi = (msg->data);
        pkt_ofs = offsetof(struct ofp_packet_in, data);
        pkt_len = ntohs(opi->header.length) - pkt_ofs;
        pkt.data = opi->data;
        pkt.size = pkt_len;
        flow_extract(&pkt, ntohs(opi->in_port), &flow);
        printf("---------------------------------\n");
        //printf("nw_src is %d\n", flow.nw_src);
        //printf("nw_dst is %d\n", flow.nw_dst);
        printf("in_port is %d\n", flow.in_port);
        //printf("dl_vlan;
        //printf("dl_type;
        //printf("tp_src;
        //printf("tp_dst;
        //printf("dl_vlan_pcp;
        //printf("nw_tos;
        //printf("nw_proto;
        printf("---------------------------------\n");
        */
        //lswitch_process_packet(sw->lswitch, sw->rconn, msg);
        ofpbuf_delete(msg);
    }
    of_add_l3_rule(sw, "10.0.0.2", "10.0.0.3", 0, 0, 100);
    if(!removed && time(NULL) - time_taken >= 50 && rconn_is_connected(sw->rconn))
        of_remove_l3_rule(sw, "10.0.0.2");

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
of_add_l3_rule(struct switch_ *sw, char *ip_src, char *ip_dst, uint32_t ip_src_mask, uint32_t ip_dst_mask, uint16_t duration)
{
    /* ip_src_mask and ip_dst_mask are currently not used, due to the mask wildcard */
    uint32_t buffer_id = -1; // Buffered packet to apply to (or -1). Not meaningful for OFPFC_DELETE*.
    uint16_t out_port1 = 1;
    uint16_t out_port2 = 2;

    struct flow flow1 = {
        inet_addr(ip_src),	// uint32_t IP source address.
        0,//inet_addr(ip_dst),	// uint32_t IP destination address.
        0,//htons(1),		// uint16_t Input switch port.
        0,//0xffff,			// uint16_t Input VLAN id.
        htons(0x0800),		// uint16_t Ethernet frame type.
        0,//htons(8),		// uint16_t TCP/UDP source port.
        0,//htons(0),		// uint16_t TCP/UDP destination port.
        {0,0,0,0,0,0},//2},		// uint8_t Ethernet source address.
        {0,0,0,0,0,0},//3},		// uint8_t Ethernet destination address.
        0,//0x00,			// uint8_t Input VLAN priority.
        0,//0x00,			// uint8_t IPv4 DSCP.
        0,//0x01,			// uint8_t IP protocol.
        {0,0,0}			// uint8_t
    };

    struct flow flow2 = {
        inet_addr(ip_dst),	// uint32_t IP source address.
        inet_addr(ip_src),	// uint32_t IP destination address.
        htons(2),		// uint16_t Input switch port.
        0xffff,			// uint16_t Input VLAN id.
        htons(0x0800),		// uint16_t Ethernet frame type.
        htons(0),		// uint16_t TCP/UDP source port.
        htons(0),		// uint16_t TCP/UDP destination port.
        {0,0,0,0,0,3},		// uint8_t Ethernet source address.
        {0,0,0,0,0,2},		// uint8_t Ethernet destination address.
        0x00,			// uint8_t Input VLAN priority.
        0x00,			// uint8_t IPv4 DSCP.
        0x01,			// uint8_t IP protocol.
        {0,0,0}			// uint8_t
    };

    /* Note: flow3 and flow4 add flows for arp, so that every arp can go from switch port1 to switch port2,
       and vice versa. I haven't think it thoroughly in theory, because I used to believe that arp will go
       from a switch port OUT to the segment that connected with this port, not across the switch. */
    struct flow flow3 = {
        0,			// uint32_t IP source address.
        0,			// uint32_t IP destination address.
        htons(1),		// uint16_t Input switch port.
        0,			// uint16_t Input VLAN id.
        htons(0x0806),		// uint16_t Ethernet frame type.
        0,			// uint16_t TCP/UDP source port.
        0,			// uint16_t TCP/UDP destination port.
        {0,0,0,0,0,0},		// uint8_t Ethernet source address.
        {0,0,0,0,0,0},		// uint8_t Ethernet destination address.
        0,			// uint8_t Input VLAN priority.
        0,			// uint8_t IPv4 DSCP.
        0,			// uint8_t IP protocol.
        {0,0,0}			// uint8_t
    };

    struct flow flow4 = {
        0,			// uint32_t IP source address.
        0,			// uint32_t IP destination address.
        htons(2),		// uint16_t Input switch port.
        0,			// uint16_t Input VLAN id.
        htons(0x0806),		// uint16_t Ethernet frame type.
        0,			// uint16_t TCP/UDP source port.
        0,			// uint16_t TCP/UDP destination port.
        {0,0,0,0,0,0},		// uint8_t Ethernet source address.
        {0,0,0,0,0,0},		// uint8_t Ethernet destination address.
        0,			// uint8_t Input VLAN priority.
        0,			// uint8_t IPv4 DSCP.
        0,			// uint8_t IP protocol.
        {0,0,0}			// uint8_t
    };

    struct ofpbuf *temp1, *temp2, *temp3, *temp4;
    struct ofp_flow_mod *ofm1, *ofm2, *ofm3, *ofm4;

    if(already_added) return;

    temp1 = make_add_simple_flow(&flow1, htonl(buffer_id), out_port2, OFP_FLOW_PERMANENT);    
    ofm1 = temp1->data;
    ofm1->match.wildcards = htonl(OFPFW_IN_PORT |
                                  OFPFW_DL_VLAN |
                                   OFPFW_DL_SRC |
                                   OFPFW_DL_DST |
                                  //OFPFW_DL_TYPE |
                                 OFPFW_NW_PROTO |
                                   OFPFW_TP_SRC |
                                   OFPFW_TP_DST |
                               //OFPFW_NW_SRC_ALL |
                               OFPFW_NW_DST_ALL |
                              OFPFW_DL_VLAN_PCP |
                                   OFPFW_NW_TOS |
                                               0);
    ofm1->priority = htons(65535);
    ofm1->hard_timeout = htons(duration);
    queue_tx(sw->lswitch, sw->rconn, temp1);

    temp2 = make_add_simple_flow(&flow2, htonl(buffer_id), out_port1, OFP_FLOW_PERMANENT);
    ofm2 = temp2->data;
    ofm2->match.wildcards = htonl(OFPFW_IN_PORT |
                                  OFPFW_DL_VLAN |
                                   OFPFW_DL_SRC |
                                   OFPFW_DL_DST |
                                  //OFPFW_DL_TYPE |
                                 OFPFW_NW_PROTO |
                                   OFPFW_TP_SRC |
                                   OFPFW_TP_DST |
                               //OFPFW_NW_SRC_ALL |
                               OFPFW_NW_DST_ALL |
                              OFPFW_DL_VLAN_PCP |
                                   OFPFW_NW_TOS |
                                               0);
    ofm2->priority = htons(65535);
    ofm2->hard_timeout = htons(duration);
    queue_tx(sw->lswitch, sw->rconn, temp2);

    temp3 = make_add_simple_flow(&flow3, htonl(buffer_id), out_port2, OFP_FLOW_PERMANENT);
    ofm3 = temp3->data;
    ofm3->match.wildcards = htonl(//OFPFW_IN_PORT |
                                  OFPFW_DL_VLAN |
                                   OFPFW_DL_SRC |
                                   OFPFW_DL_DST |
                                  //OFPFW_DL_TYPE |
                                 OFPFW_NW_PROTO |
                                   OFPFW_TP_SRC |
                                   OFPFW_TP_DST |
                               OFPFW_NW_SRC_ALL |
                               OFPFW_NW_DST_ALL |
                              OFPFW_DL_VLAN_PCP |
                                   OFPFW_NW_TOS |
                                               0);
    ofm3->priority = htons(65535);
    ofm3->hard_timeout = htons(duration);
    queue_tx(sw->lswitch, sw->rconn, temp3);

    temp4 = make_add_simple_flow(&flow4, htonl(buffer_id), out_port1, OFP_FLOW_PERMANENT);
    ofm4 = temp4->data;
    ofm4->match.wildcards = htonl(//OFPFW_IN_PORT |
                                  OFPFW_DL_VLAN |
                                   OFPFW_DL_SRC |
                                   OFPFW_DL_DST |
                                  //OFPFW_DL_TYPE |
                                 OFPFW_NW_PROTO |
                                   OFPFW_TP_SRC |
                                   OFPFW_TP_DST |
                               OFPFW_NW_SRC_ALL |
                               OFPFW_NW_DST_ALL |
                              OFPFW_DL_VLAN_PCP |
                                   OFPFW_NW_TOS |
                                               0);
    ofm4->priority = htons(65535);
    ofm4->hard_timeout = htons(duration);
    queue_tx(sw->lswitch, sw->rconn, temp4);

    already_added = true; /* actually it is not sent by rconn yet, rconn_send put 
                             it in the queue and rconn_run takes care of it */
    printf("flow added\n");time_taken = time(NULL);
}

static void
of_remove_l3_rule(struct switch_ *sw, char * ip_src)
{
    struct flow flow = {
        inet_addr(ip_src),	// uint32_t IP source address.
        0,			// uint32_t IP destination address.
        0,			// uint16_t Input switch port.
        0,			// uint16_t Input VLAN id.
        htons(0x0800),		// uint16_t Ethernet frame type.
        0,			// uint16_t TCP/UDP source port.
        0,			// uint16_t TCP/UDP destination port.
        {0,0,0,0,0,0},		// uint8_t Ethernet source address.
        {0,0,0,0,0,0},		// uint8_t Ethernet destination address.
        0,			// uint8_t Input VLAN priority.
        0,			// uint8_t IPv4 DSCP.
        0,			// uint8_t IP protocol.
        {0,0,0}			// uint8_t
    };
    struct ofpbuf *temp;
    struct ofp_flow_mod *ofm;

    temp = make_del_flow(&flow);
    ofm = temp->data;
    ofm->match.wildcards = htonl(OFPFW_IN_PORT |
                                 OFPFW_DL_VLAN |
                                  OFPFW_DL_SRC |
                                  OFPFW_DL_DST |
                                 //OFPFW_DL_TYPE |
                                OFPFW_NW_PROTO |
                                  OFPFW_TP_SRC |
                                  OFPFW_TP_DST |
                              //OFPFW_NW_SRC_ALL |
                              OFPFW_NW_DST_ALL |
                             OFPFW_DL_VLAN_PCP |
                                  OFPFW_NW_TOS |
                                              0);

    //ofm->command = OFPFC_DELETE;
    ofm->priority = htons(65535);
    //ofm->hard_timeout = htons(100);
    //ofm->buffer_id = htonl(-1);

    queue_tx(sw->lswitch, sw->rconn, temp);
    removed = true;
    printf("flow removed\n");
    /*struct ofp_flow_mod *ofm;
    struct ofpbuf *b;
    struct ofp_match match = {
        0,//-285198336,	// Wildcard fields.
        0,		// Input switch port.
        {0,0,0,0,0,0},	// Ethernet source address.
        {0,0,0,0,0,0},	// Ethernet destination address.
        0,		// Input VLAN id.
        0,		// Input VLAN priority.
        {0},		// Align to 64-bits
        0,//8,		// Ethernet frame type.
        0,		// IP ToS (actually DSCP field, 6 bits).
        0,		// IP protocol or lower 8 bits of ARP opcode.
        {0,0},		// Align to 64-bits
        0,//33554442,	// IP source address.
        0,		// IP destination address.
        0,		// TCP/UDP source port.
        0,		// TCP/UDP destination port.
    };

    ofm = make_openflow(offsetof(struct ofp_flow_mod, actions),
                        OFPT_FLOW_MOD, &b);
    ofm->match = match;



    //ofm->match.wildcards = htonl(OFPFW_IN_PORT |
    //                             OFPFW_DL_VLAN |
    //                              OFPFW_DL_SRC |
    //                              OFPFW_DL_DST |
    //                             OFPFW_DL_TYPE |
    //                            OFPFW_NW_PROTO |
    //                              OFPFW_TP_SRC |
    //                              OFPFW_TP_DST |
    //                          OFPFW_NW_SRC_ALL |
    //                          OFPFW_NW_DST_ALL |
    //                         OFPFW_DL_VLAN_PCP |
    //                              OFPFW_NW_TOS |
    //                                          0);



    ofm->command = OFPFC_DELETE;
    ofm->out_port = htons(OFPP_NONE);
    ofm->priority = htons(65535);
    if (!rconn_is_connected(sw->rconn)) {
            printf("of_remove_l3_rule: sw->rconn not connected\n");
    } else {
            printf("of_remove_l3_rule: sw->rconn is good\n");
    }
    rconn_send(sw->rconn, b, NULL);printf("flow removed\n");removed = true;*/
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
