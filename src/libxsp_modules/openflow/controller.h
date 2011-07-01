#ifndef CONTROLLER_H
#define CONTROLLER_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>

void controller_init(int, char **);
void controller_start();
void controller_stop();
void of_add_l3_rule(char *, char *, uint32_t, uint32_t, uint16_t);
void of_remove_l3_rule(char *, char *, uint32_t, uint32_t);

#ifdef __cplusplus
}
#endif

#endif
