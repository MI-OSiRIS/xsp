#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "xsp_logger.h"
#include "xsp_config.h"
#include "xsp_tpool.h"
#include "xsp_modules.h"
#include "xsp_settings.h"
#include "xsp_session.h"
#include "xsp_conn.h"
#include "xsp_main_settings.h"

#include "option_types.h"
#include "compat.h"
#include "queue.h"

int xspd_speedometer_init();
int xspd_speedometer_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block);

enum speedometer_types {
    XSPD_SPEEDOMETER_IN = 0,
    XSPD_SPEEDOMETER_OUT,
    XSPD_SPEEDOMETER_INIT
};

typedef struct speedometer_sample {
    uint64_t value;
    time_t time;
    uint8_t type;
    TAILQ_ENTRY(speedometer_sample) samples;
} speedometer_sample_t;


static pthread_mutex_t values_mtx;
static TAILQ_HEAD(speedometer_values_head, speedometer_sample) values;


static xspModule xspd_speedometer_module = {
    .desc = "Speed-o-meter Module",
	.dependencies = "",
    .init = xspd_speedometer_init,
    .opt_handler = xspd_speedometer_opt_handler
};

static int num_samples;
static char *samples_dir;
static short int server_port;
static pthread_t server;

xspModule *module_info() {
    return &xspd_speedometer_module;
}

static void *xspd_speedometer_server(void *arg) {
    int sockfd;
    int newfd;
    socklen_t addr_size;
    struct sockaddr_in my_addr;
    struct sockaddr_storage their_addr;
    char buffer[4192];

    sockfd = socket(PF_INET, SOCK_STREAM, 0);

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(server_port);     // short, network byte order
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(my_addr.sin_zero, '\0', sizeof(my_addr.sin_zero));

    bind(sockfd, (struct sockaddr *)&my_addr, sizeof my_addr);
    listen(sockfd, 5);

    addr_size = sizeof(their_addr);

    while (1) {
        int res;
        newfd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        res = recv(newfd, &buffer, 4192, 0);
        if (res == 0)
            continue;
    }

    return NULL;
}

int xspd_speedometer_init() {
    int i;
    int port;
    time_t current_time;
    xspSettings *settings = xsp_main_settings();

    if (xsp_settings_get_int_2(settings, "speedometer", "num_samples", &num_samples) != 0) {
        num_samples = 180;
    }

    if (xsp_settings_get_int_2(settings, "speedometer", "server_port", &port) != 0)
        server_port = 7272;
    else
        server_port = (short) port;

    if (xsp_settings_get_2(settings, "speedometer", "samples_dir", &samples_dir) != 0) {
        samples_dir = "/tmp";
    }

    TAILQ_INIT(&values);
    pthread_mutex_init(&values_mtx, NULL);

    current_time = time(NULL);
    for (i = 0; i < num_samples; i++) {
        speedometer_sample_t *sample = malloc(sizeof(speedometer_sample_t));
        sample->time = current_time;
        sample->type = XSPD_SPEEDOMETER_INIT;
        sample->value = 0;
        TAILQ_INSERT_TAIL(&values, sample, samples);
    }

    //pthread_create(&server, NULL, xspd_speedometer_server, NULL);

    return 0;
}

static void add_sample(speedometer_sample_t *s) {
    speedometer_sample_t *first;

    xsp_info(8, "received value=%llu time=%u type=%hu", s->value, s->time, s->type);

    speedometer_sample_t *sample = malloc(sizeof(speedometer_sample_t));
    // XXX(fernandes): globus side doesn't have TAILQ entry.
    sample->value = s->value;
    sample->time = s->time;
    sample->type = s->type;

    pthread_mutex_lock(&values_mtx);
    {
        first = TAILQ_FIRST(&values);
        TAILQ_INSERT_TAIL(&values, sample, samples);
        TAILQ_REMOVE(&values, first, samples);
    }
    pthread_mutex_unlock(&values_mtx);

    free(first);
}

static void dump_samples() {
    int i;
    char file[255];
    char date[30];
    speedometer_sample_t *next;
    FILE *graphfile;
    FILE *infile;
    FILE *outfile;

    pthread_mutex_lock(&values_mtx);
    {

    sprintf(file, "%s/speedometer_graph_samples.json", samples_dir);
    graphfile = fopen(file, "w+");

    sprintf(file, "%s/speedometer_in_samples.json", samples_dir);
    infile = fopen(file, "w+");

    sprintf(file, "%s/speedometer_out_samples.json", samples_dir);
    outfile = fopen(file, "w+");

    fprintf(graphfile,
"{\"Results\":\n"
"[\n"
            );

    fprintf(infile,
"{\"servdata\": {\n"
"    \"data\": [\n"
            );

    fprintf(outfile,
"{\"servdata\": {\n"
"    \"data\": [\n"
            );

    i = 0;
    TAILQ_FOREACH(next, &values, samples) {
        // Transform values to Gb/s
        float read = (next->type & XSPD_SPEEDOMETER_IN) ? next->value / 125000000.0: 0;
        float write = (next->type & XSPD_SPEEDOMETER_OUT) ? next->value / 125000000.0 : 0;
        strftime (date, 30, "%m/%d/%Y %H:%M:%S", localtime(&next->time));

        fprintf(graphfile,
                "{\"date\":\"%s\", \"inspeed\":\"%.2f\", \"outspeed\":\"%.2f\"},\n",
                date, read, write);

        if (i >= (num_samples - 6)) {
            fprintf(infile,  "        [%u,%.2f],\n", next->time, read);
            fprintf(outfile, "        [%u,%.2f],\n", next->time, write);
        }

        i++;
    }
    // Remove last comma
    fseek(graphfile, -2, SEEK_CUR);
    fprintf(graphfile, "\n]}\n");
    fclose(graphfile);

    fprintf(infile, ""
"      ]\n"
"    }\n"
"}\n");
    fclose(infile);

    fprintf(outfile, ""
"      ]\n"
"    }\n"
"}\n");
    fclose(outfile);

    }
    pthread_mutex_unlock(&values_mtx);
}

static void transfer_samples() {
    char command[255];
    FILE *c;
    sprintf(command, "/usr/bin/scp %s/speedometer* iu-srs.sc11.org:speedometer/ &> /dev/null", samples_dir);
    c = popen(command, "r");
    pclose(c);
}

int xspd_speedometer_opt_handler(comSess *sess, xspBlock *block, xspBlock **ret_block) {

    xsp_info(8, "handling speedometer message of type: %d", block->type);
    // block->data has the data of length block->length

    switch(block->type) {
    case SPEEDOMETER_UPDATE:
      {
        add_sample((speedometer_sample_t*)block->data);
        dump_samples();
        transfer_samples();
        *ret_block = NULL;
      }
      break;
    default:
        break;

    }

    return 0;
}
