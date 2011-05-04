#ifndef XSPD_TPOOL_H
#define XSPD_TPOOL_H

int xspd_tpool_init();
int xspd_tpool_exec(void *(*fn) (void *), void *arg);

#endif
