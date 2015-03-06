 /* 
    Copyright (c) 2009-2010, 
    The Regents of the University of California, through 
    Lawrence Berkeley National Laboratory (subject to receipt of any required 
    approvals from the U.S. Dept. of Energy).  All rights reserved.
  */
static const volatile char rcsid[] ="$Id: netlogger_calipers.c 33086 2012-11-12 18:23:45Z dang $";

#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* BSON */
#include "bson.h"

/* Interface */
#include "netlogger_calipers.h"

/* ---------------------------------------------------------------
 * Utility functions
 */

static int format_iso8601(struct timeval *tv, char *buf);

/**
 * Format a time per ISO8601.
 * Format is: YYYY-MM-DDThh:mm:ss.<fractional>
 *
 * @param tv Time
 * @param buf Buffer to format into (allocated)
 * @return 0 on success, -1 on error
 */
int format_iso8601(struct timeval *tv, char *buf)
{
    int i;
    long usec;
    struct tm *tm_p;
	time_t *time_p;

	time_p = (time_t *)&(tv->tv_sec);
	if ( NULL == time_p ) {
		goto error;
	}
	tm_p = gmtime(time_p);
    if (NULL == tm_p) {
        goto error;
	}

    if (0 == strftime(buf, 21, "%Y-%m-%dT%H:%M:%S.", tm_p))
        goto error;

    /* add in microseconds */
    usec = tv->tv_usec;
    for (i = 0; i < 6; i++) {
        buf[25 - i] = '0' + (usec % 10);
        usec /= 10;
    }

    /* add 'Z'  and trailing NUL */
    buf[26] = 'Z';
    buf[27] = '\0';

    return 27;

  error:
    return -1;
}

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#endif

/* ---------------------------------------------------------------
 * Streaming variance methods
 */

#define WVAR_VARIANCE(W) \
(((W).count < (W).min_items) ? -1 : (W).t / ((W).count - 1))

#define WVAR_SD(W) \
(((W).count < (W).min_items) ? -1 : sqrt((W).t / ((W).count - 1)))

void netlogger_wvar_clear(struct netlogger_wvar_t *self) 
{
    self->m = self->t = 0.0;
    self->count = 0;
}

/* ---------------------------------------------------------------
 * Kahan sum methods
 */

void netlogger_ksum_clear(struct netlogger_ksum_t *self, double x0)
{
    self->s = x0;
    self->c = 0;
}

/* ---------------------------------------------------------------
 * NetLogger calipers methods
 */

#define T netlogger_calipers_T

static void
nl_calipers_hist_init(T self, unsigned n, double min, double width);
     
T netlogger_calipers_new(unsigned min_items)
{
    T self = (T)malloc(sizeof(struct netlogger_calipers_t));
    self->var.min_items = min_items;
    self->rvar.min_items = min_items;
    self->gvar.min_items = min_items;
    self->h_state = NL_HIST_OFF;
    self->h_gdata = NULL;
    netlogger_calipers_clear(self);
    return self;
}

/**
 * Allocate space and turn on histogramming.
 */
void netlogger_calipers_hist_manual(T self, unsigned n, double min, double max)
{
    double width;
    
    self->h_state = NL_HIST_MANUAL;

    if (n > NL_MAX_HIST_BINS) {
        n = NL_MAX_HIST_BINS;
        /* TODO: Warn user! */
    }
    width = (max - min) / n;
    nl_calipers_hist_init(self, n, min, width);
}

/**
 * Allocate space and turn on histogramming,
 * for auto-histogram method.
 */
 void netlogger_calipers_hist_auto(T self, unsigned n, unsigned m)
 {
     self->h_state = NL_HIST_AUTO_PRE;
     self->h_auto_pre = m;
     nl_calipers_hist_init(self, n, DBL_MAX, 0);
     self->h_gmax = DBL_MIN; /* reset after hist_init */
 }


/* Internal method for shared constructor code. */
void nl_calipers_hist_init(T self, unsigned n, double min, double width)
{
    if (NULL != self->h_gdata) {
        free(self->h_gdata);
        self->h_gdata = NULL;
    }
    if (0 == n) {
        self->h_state = NL_HIST_OFF;
    }
    else {
        self->h_num = n;
        self->h_gmin = min;
        self->h_gwidth = width;
        self->h_gmax = min + width * n;
        self->h_gdata = (unsigned *)malloc(sizeof(unsigned) * n);
        memset(self->h_gdata, 0, sizeof(unsigned)*n);
    }
}

void netlogger_calipers_clear(T self)
{
    netlogger_ksum_clear(&self->ksum, 0);
    netlogger_ksum_clear(&self->krsum, 0);
    netlogger_ksum_clear(&self->kgsum, 0);
    netlogger_wvar_clear(&self->var);
    netlogger_wvar_clear(&self->rvar);
    netlogger_wvar_clear(&self->gvar);
    self->sd = self->rsd = self->gsd = 0;
    self->min = self->rmin = self->gmin = DBL_MAX;
    self->max = self->rmax = self->gmax = 0;
    self->dur = self->dur_sum = 0;
    memset(&self->first, 0, sizeof(self->first));
    self->count = 0;
    self->rcount = 0;
    self->is_begun = 0;
    self->dirty = 0;
    if (self->h_state != NL_HIST_OFF) {
        /* clear histogram data */
        memset(self->h_gdata, 0, sizeof(unsigned)*self->h_num);
    }
}

void netlogger_calipers_calc(T self)
{
    if (self->dirty && (self->count > 0)) {
        self->sum  = self->ksum.s;
        self->rsum = self->krsum.s;
        self->gsum = self->kgsum.s;
        self->mean = self->sum / self->count;
        self->rmean = self->rsum / self->rcount;
        self->gmean = self->gsum / self->rcount;
        self->sd = WVAR_SD(self->var);
        self->rsd = WVAR_SD(self->rvar);
        self->gsd = WVAR_SD(self->gvar);
        self->dur = self->end.tv_sec - self->first.tv_sec + 
            (self->end.tv_usec - self->first.tv_usec) / 1e6;
        self->dirty = 0;
        if (self->h_state == NL_HIST_AUTO_PRE) {
#           define NSD 3
			if (self->gsd >= 0) {
				/* with stdev, pick range mean +/- NSD*stdev */
				self->h_gmin = MIN(self->h_gmin,
								   self->gmean - NSD*self->gsd);
				self->h_gmax = MAX(self->h_gmax,
								   self->gmean + NSD*self->gsd);
			}
			else {
				/* no stdev, just use full data range */
				self->h_gmin = self->gmin;
				self->h_gmax = self->gmax;
			}
			/* If there is a range, set width */
			if (self->h_gmax > self->h_gmin) {
				self->h_gwidth = (self->h_gmax - self->h_gmin) 
							 / (double)self->h_num;
			}
		/*	printf("@@ %lf  ; %lf ; %lf:%lf\n", self->h_gmin, self->h_gmax, self->gmean, self->gsd); */
            if (0 == --self->h_auto_pre) {
                self->h_state = NL_HIST_AUTO_READY;
            }
        }
        else if (self->h_state == NL_HIST_AUTO_READY) {
            self->h_state = NL_HIST_AUTO_FULL; /* ready to report */
        }
    }
}

#define LOG_BUFSZ 1024
char *netlogger_calipers_log(T self,
                             const char *event)
{
    struct timeval now;
    char *msg;
    char *ts, *p;
    int msg_size, len;

    gettimeofday(&now, NULL);
    if (self->dirty) {
        netlogger_calipers_calc(self);
    }
    msg_size = LOG_BUFSZ;
    p = msg = malloc(msg_size);
    if (NULL == p) {
        return NULL;
    }
    strcpy(p, "ts=");
    p += 3;
    len = format_iso8601(&now, p);
    if ( -1 == len ) goto error;
    p += len;
    len = sprintf(p, " event=%s "
            "v.sum=%lf v.min=%lf v.max=%lf v.mean=%lf v.sd=%lf "
            "r.sum=%lf r.min=%lf r.max=%lf r.mean=%lf r.sd=%lf "
            "g.sum=%lf g.min=%lf g.max=%lf g.mean=%lf g.sd=%lf "
            "count=%lld dur=%lf dur.i=%lf",
            event,
            self->sum, self->min, self->max, self->mean, self->sd, 
            self->rsum, self->rmin, self->rmax, self->rmean, self->rsd,
            self->gsum, self->gmin, self->gmax, self->gmean, self->gsd,
            self->count, self->dur, self->dur_sum);
    if (-1 == len) goto error;
    p += len;
    /* histogram */
    if (NL_HIST_HAS_DATA(self)) {
        int i, need, avail;
        char numbuf[4096];
        double h_gmax = self->h_gmin + self->h_gwidth * self->h_num;

        /* see if all values will fit */
        avail = msg_size - (int)(p - msg) - 1;
        need = 0;
        need += 6*4; /* space + h.gd=, h.gw=, h.gm= h.gx= */
        need += sprintf(numbuf, "%lf", self->h_gmin);
        need += sprintf(numbuf, "%lf", h_gmax);
        need += sprintf(numbuf, "%lf", self->h_gwidth);
        for (i=0; i < self->h_num; i++) {
            need += 1 + sprintf(numbuf, "%d", self->h_gdata[i]);
        }
        /* if they fit, then add histogram */
        if (need <= avail) {
            /* - gap - */
            p += sprintf(p, " h.gm=%lf", self->h_gmin);
            p += sprintf(p, " h.gx=%lf", h_gmax);
            p += sprintf(p, " h.gw=%lf", self->h_gwidth);
            p += sprintf(p, " h.gd=");
            /* print each buckets' size */
            for (i=0; i < self->h_num-1; i++) {
                p += sprintf(p, "%d,", self->h_gdata[i]);
            }
            /* final one without trailing delimiter */
            p += sprintf(p, "%d", self->h_gdata[self->h_num - 1]);
        }
    }
    return msg;
error:
    if (msg) free(msg);
    return NULL;
}

/**
 * Build perfSONAR data block.

    Format::
    
      'mid' : <metadata-id>
      'data' : { 
        'ts' : (double)timestamp in sec. since 1/1/1970,
        '_sample' : (int)sample number,
        '<field>' : <value>,
        ...more fields and values..
       }

 */
bson *netlogger_calipers_psdata(T self, const char *event, const char *m_id,
                                int32_t sample_num)
{
    struct timeval now;
    bson_buffer bb;
    bson *bp = NULL;
   
    assert(self && event && m_id);

    gettimeofday(&now, NULL);
    if (self->dirty) {
        netlogger_calipers_calc(self);
    }
    
    bson_buffer_init(&bb);
    bson_ensure_space(&bb, LOG_BUFSZ);
    
    bson_append_string(&bb, "mid", m_id);
    bson_append_start_object(&bb, "data");
    bson_append_double(&bb, "ts", now.tv_sec + now.tv_usec/1e6);
    bson_append_int(&bb, "_sample", sample_num);
    bson_append_double(&bb, "sum_v", self->sum);
    bson_append_double(&bb, "min_v", self->min);
    bson_append_double(&bb, "max_v", self->max);
    bson_append_double(&bb, "mean_v", self->mean);
    bson_append_double(&bb, "sd_v", self->sd);
    bson_append_double(&bb, "sum_r", self->rsum);
    bson_append_double(&bb, "min_r", self->rmin);
    bson_append_double(&bb, "max_r", self->rmax);
    bson_append_double(&bb, "mean_r", self->rmean);
    bson_append_double(&bb, "sd_r", self->rsd);
    bson_append_double(&bb, "sum_g", self->gsum);
    bson_append_double(&bb, "min_g", self->gmin);
    bson_append_double(&bb, "max_g", self->gmax);
    bson_append_double(&bb, "mean_g", self->gmean);
    bson_append_double(&bb, "sd_g", self->gsd);
    bson_append_int(&bb, "count", self->count);
    bson_append_double(&bb, "dur", self->dur);
    bson_append_double(&bb, "dur_inst", self->dur_sum);
    /* add histogram data, if being recorded */
    if (self->h_state == NL_HIST_AUTO_FULL) {
        int i;
        char idx[16];
        /* gap hist */
        bson_append_double(&bb, "h_gm", self->h_gmin);
        bson_append_double(&bb, "h_gw", self->h_gwidth);
        bson_append_start_array(&bb, "h_gd");
        for (i=0; i < self->h_num; i++) {
            sprintf(idx, "%d", i);
            bson_append_int(&bb, idx, self->h_gdata[i]);            
        }
        bson_append_finish_object(&bb);
    }

    bson_append_finish_object(&bb);

    bp = malloc(sizeof(bson));
    bson_from_buffer(bp, &bb);

    return(bp);

 error:
    if (bp) {
        bson_destroy(bp);
        free(bp);
    }
    bson_buffer_destroy(&bb);
    return(NULL);
}

void netlogger_calipers_free(T self)
{
    if (self) {
        if (NULL != self->h_gdata)
            free(self->h_gdata);        
        free(self);
    }
}

#undef T
