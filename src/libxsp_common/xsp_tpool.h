#ifndef XSP_TPOOL_H
#define XSP_TPOOL_H

int xsp_tpool_init();
int xsp_tpool_exec(void *(*fn) (void *), void *arg);

#endif
