#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "xspd_tpool.h"
#include "xspd_config.h"

// Definitions
struct tpool_entry
{
	pthread_t thread;
	void *(*fn) (void *);
	void *arg;
//	pthread_mutex_t lock;
//	pthread_cond_t wait_run;
//	short status;
};

#define TPOOL_INIT    0x01
#define TPOOL_WAITING 0x02
#define TPOOL_RUNNING 0x03

#define TPOOL_INCREMENT 5


// variables
static struct tpool_entry **pool;

static int pool_size;

static pthread_mutex_t tpool_add_lock;

static pthread_attr_t pt_attr;

// functions
static struct tpool_entry *alloc_tpool_entry();
static void free_tpool_entry(struct tpool_entry *tpool);
static void *tpool_thread_run(void *arg);

struct xspd_tpool_config_t {
	unsigned int min_threads;
};

static struct xspd_tpool_config_t xspdTpoolConfig = {
	.min_threads = 1
};

void xspd_tpool_read_config() {
	int val;

	if (xspd_main_settings_get_int("tpool", "min_threads", &val) == 0) {
		if (val >= 0)
			xspdTpoolConfig.min_threads = val;
	}
}

/*
 *  int xspd_tpool_init():
 *      This function initializes the thread pool.
 */
int xspd_tpool_init() {
	int i;

	xspd_tpool_read_config();

	// initialize the add mutex
	if (pthread_mutex_init(&tpool_add_lock, 0) != 0) {
		fprintf(stderr, "xspd_tpool_init(): couldn't initialize thread pool lock\n");
		goto error_exit;
	}

	if (pthread_attr_init((pthread_attr_t *)&pt_attr) != 0) {
		fprintf(stderr, "xspd_tpool_init(): couldn't initialize thread attributes\n");
		goto error_exit2;
	}

#if !defined(FREEBSD)
	if (pthread_attr_setscope((pthread_attr_t *)&pt_attr, PTHREAD_SCOPE_SYSTEM) != 0) {
		fprintf(stderr, "xspd_tpool_init(): couldn't set thread scope\n");
		goto error_exit2;
	}
#endif

	// allocate space for a series of pointers

	pool = (struct tpool_entry **) malloc(sizeof(struct tpool_entry *) * xspdTpoolConfig.min_threads);
	if (!pool) {
		fprintf(stderr, "xspd_tpool_init(): error allocating thread pool\n");
		goto error_exit3;
	}

	// NULL the pointer list
	bzero(pool, sizeof(struct tpool_entry *) * xspdTpoolConfig.min_threads);

	// allocate new thread pool entries
	for(i = 0; i < xspdTpoolConfig.min_threads; i++)
	{
		pool[i] = alloc_tpool_entry();
		if (pool[i] == NULL) {
			fprintf(stderr, "xspd_tpool_init(): error allocating initial threads\n");
			goto error_exit4;
		}
	}

	pool_size = xspdTpoolConfig.min_threads;

	return 0;

error_exit4:
	// on error, go through and free all the stuff we allocated
	for(i = 0; i < xspdTpoolConfig.min_threads; i++)
	{
		if (pool[i] != NULL)
			free_tpool_entry(pool[i]);
	}

	free(pool);
error_exit3:
	pthread_attr_destroy(&pt_attr);
error_exit2:
	pthread_mutex_destroy(&tpool_add_lock);
error_exit:
	return -1;
}

/*
 *  struct tpool_entry *alloc_tpool_entry():
 *       This function allocates a new thread pool entry and creates a thread
 *       for it.
 */
static struct tpool_entry *alloc_tpool_entry()
{
	struct tpool_entry *retval;

	// allocate a thread pool entry
	retval = (struct tpool_entry *) malloc(sizeof(struct tpool_entry));
	if (!retval)
		goto error_exit;

	// initialize the mutex and condition variables
//	if (pthread_mutex_init(&retval->lock, 0))
//		goto error_exit2;

//	if (pthread_cond_init(&retval->wait_run, 0))
//		goto error_exit3;

	// set the function/args to default values
	retval->fn = NULL;

	retval->arg = NULL;

	// set the status
//	retval->status = TPOOL_INIT;

	// create an associated thread
//	if (pthread_create(&retval->thread, &pt_attr, tpool_thread_run, retval) != 0)
//	    goto error_exit4;

	// give it to the user
	return retval;

//error_exit4:
//	pthread_cond_destroy(&retval->wait_run);
//error_exit3:
//	pthread_mutex_destroy(&retval->lock);
//error_exit2:
//	free(retval);
error_exit:
	return NULL;
}

static void free_tpool_entry(struct tpool_entry *tpool) {
//    pthread_mutex_destroy(&tpool->lock);
//    pthread_cond_destroy(&tpool->wait_run);
//    pthread_cancel(tpool->thread);
//    free(tpool);
}

/*
 *  void *tpool_thread_run(void *arg):
 *      This function is the function run by all the thread pool threads. It
 *      detaches and then waits for a signal. When it receives the signal, it
 *      executes its function and then goes back to waiting. Lather, rinse, repeat.
 */
/*
static void *tpool_thread_run(void *arg)
{
	struct tpool_entry *self = (struct tpool_entry *) arg;

	pthread_detach(pthread_self());

	// we take the lock and here and "give it up" when we do the
	// pthread_cond_wait
	pthread_mutex_lock(&self->lock);

	while(1)
	{
	    // this is to prevent a deadlock where a thread is
	    // allocated and used before it is run. The calling thread
	    // signals the thread before it has a chance to cond_wait

	    if (self->status != TPOOL_RUNNING)
	    {
		self->status = TPOOL_WAITING;
		
		pthread_cond_wait(&self->wait_run, &self->lock);
	    }
	    
	    self->fn(self->arg);
	    
	    self->status = TPOOL_WAITING;
	}

	return NULL;
}
*/

/*
 *  void xspd_tpool_exec(void *(*fn) (void *), void *arg):
 *      This function finds an available thread to run the specified
 *      function(expanding the number of threads if need be).
 */
/*
int xspd_tpool_exec(void *(*fn) (void *), void *arg) {
	int i, j, target;
	struct tpool_entry **new_pool;
	int new_pool_size;

	pthread_mutex_lock(&tpool_add_lock);

	// find a free thread
	for(i = 0; i < pool_size; i++)
	{
		// if we have a free thread
		if (pool[i]->status == TPOOL_WAITING)
		{
			target = i;
			goto out;
		}
	}

	// allocate more space for new threads
	new_pool = (struct tpool_entry **) realloc(pool, sizeof(struct tpool_entry *) * (pool_size + TPOOL_INCREMENT));
	if (!new_pool)
		return -1;

	pool = new_pool;

	// we need more threads scotty
	new_pool_size = pool_size + TPOOL_INCREMENT;

	// initialize the newly allocated space with new threads
	for(j = pool_size; j < new_pool_size; j++) {
		pool[j] = alloc_tpool_entry();
		if (!pool[j])
			break;
	}


	if (j == pool_size) { // i.e. we have allocated nothing
		return -1;
	}

	// j would be the actual number of threads we could allocate
	new_pool_size = j;

	target = pool_size;

	pool_size = new_pool_size;

out:
	// set the function/arguments and have the new thread run
	pthread_mutex_lock(&pool[target]->lock);
	{
		pool[target]->status = TPOOL_RUNNING;
		pool[target]->fn = fn;
		pool[target]->arg = arg;
	}
	pthread_mutex_unlock(&pool[target]->lock);

	pthread_cond_signal(&pool[target]->wait_run);

	pthread_mutex_unlock(&tpool_add_lock);

	return 0;
}
*/

/*
 *  void *tpool_thread_run(void *arg):
 *      This function is the function run by all the thread pool threads. It
 *      detaches and then waits for a signal. When it receives the signal, it
 *      executes its function and then goes back to waiting. Lather, rinse, repeat.
 */
static void *tpool_thread_run(void *arg)
{
        struct tpool_entry *self = (struct tpool_entry *) arg;

        pthread_detach(pthread_self());

        self->fn(self->arg);

//        free_tpool_entry(self);

        return NULL;
}

/*
 *  void xspd_tpool_exec(void *(*fn) (void *), void *arg):
 *      This function finds an available thread to run the specified
 *      function(expanding the number of threads if need be).
 */
int xspd_tpool_exec(void *(*fn) (void *), void *arg) {
        int i, j, target;
        struct tpool_entry *entry;
        int new_pool_size;
        int n;

        entry = alloc_tpool_entry();

        // set the function/arguments and have the new thread run
//        pthread_mutex_lock(&entry->lock);
//        {
//                entry->status = TPOOL_RUNNING;
                entry->fn = fn;
                entry->arg = arg;
//        }
//        pthread_mutex_unlock(&entry->lock);

	    return pthread_create(&entry->thread, &pt_attr, tpool_thread_run, entry);

//        pthread_cond_signal(&entry->wait_run);
}

