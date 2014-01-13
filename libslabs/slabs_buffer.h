#ifndef SLABS_BUFFER_H
#define SLABS_BUFFER_H

#include <stdint.h>
#include "pthread.h"

#define FALSE            0
#define TRUE             1

#define SLAB_READ         0
#define SLAB_WRITE        1
#define SLAB_CURR         2

#define SLAB_NO_ERR       0x00
#define SLAB_NOT_SENT     0x01
#define SLAB_SENT_NO_ACK  0x02
#define SLAB_SEND_FAIL    0x04
#define SLAB_READ_FAIL    0x08
#define SLAB_BACKEND_DONE 0x10
#define SLAB_SEND_READY   0x20
#define SLAB_RECV_READY   0x40
#define SLAB_INUSE        0x80

typedef struct slabs_buf_entry_t {
	uint64_t size;
	void *base;
	void *ptr;
	void *priv;
	int empty;
	uint64_t read_amount;
	uint64_t write_amount;
	int status;
} bufEntry;

typedef struct slabs_xfer_buf_t
{
	bufEntry **entries;
	int p_count;
	int r_index;
	int w_index;
	int s_index;
	
	int status;
	uint64_t size;
	uint64_t p_size;
	uint64_t total_count_bytes;

	pthread_mutex_t buf_lock;
	pthread_cond_t read_cond;
	pthread_cond_t write_cond;
} SLAB;

extern uint64_t buf_total_bytes;
extern pthread_mutex_t buf_total_lock;
extern pthread_cond_t buf_total_cond;
extern uint64_t SLAB_SIZE;

SLAB *slabs_buf_create(uint64_t size, uint64_t alloc_size, int partitions);
void slabs_buf_free(SLAB *slab);
void slabs_buf_reset(SLAB *slab);
void slabs_buf_reset_ind(SLAB *slab, int ind);

void slabs_buf_set_read_index(SLAB *slab, int ind);
void slabs_buf_set_write_index(SLAB *slab, int ind);

void slabs_buf_unset_pstatus(SLAB *slab, int status, int side);
void slabs_buf_set_pstatus(SLAB *slab, int status, int side);
int slabs_buf_get_pstatus(SLAB *slab, int side);
void slabs_buf_set_status(SLAB *slab, int status);
int slabs_buf_get_status(SLAB *slab);
uint64_t slabs_buf_get_size(SLAB *slab);
uint64_t slabs_buf_get_psize(SLAB *slab);
uint64_t slabs_buf_get_pcount(SLAB *slab);

void slabs_buf_set_priv_data_ind(SLAB *slab, void *data, int ind);
void *slabs_buf_get_priv_data_ind(SLAB *slab, int ind);
void *slabs_buf_get_priv_data(SLAB *slab, int side);

void slabs_buf_wait_curr(SLAB *slab, int side);
void slabs_buf_curr_swap(SLAB *slab);
void slabs_buf_read_swap(SLAB *slab, int total);
void slabs_buf_write_swap(SLAB *slab, int total);

void *slabs_buf_addr(SLAB *slab, int side);
void *slabs_buf_addr_ind(SLAB *slab, int ind);
void slabs_buf_advance_curr(SLAB *slab, uint64_t bytes, int side);
void slabs_buf_advance(SLAB *slab, uint64_t bytes, int side);
uint64_t slabs_buf_count_bytes(SLAB *slab, int side);
uint64_t slabs_buf_count_bytes_free(SLAB *slab, int side);

void *slabs_buf_get_free(SLAB *slab, uint64_t *ret_size, int *ret_ind);

#endif
