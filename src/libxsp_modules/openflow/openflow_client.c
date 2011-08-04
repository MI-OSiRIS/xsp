#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "controller.h"

int main() {
    char str[64];
    char *argv[2] = {"controller", "ptcp:"}; /* openflow offical controller has
                                                details about the input arguments */

    /* first, initialize the controller */
    controller_init(2, argv);

    /* start the controller */
    controller_start();

    /* add a flow from the console */
    printf("IP address to add: ");
    fgets(str, 64, stdin);
    if(str[strlen(str) - 1] == '\n') 
        str[strlen(str) - 1] = '\0';

    printf("adding %s to the switch\n", str);
    of_add_l3_rule(str, "10.0.0.3", 0, 0, 100); // hard code the dst to .3

    /* remove a flow */
    printf("IP address to remove: ");
    fgets(str, 64, stdin);
    if(str[strlen(str) - 1] == '\n') 
        str[strlen(str) - 1] = '\0';

    printf("removing %s from the switch\n", str);
    of_remove_l3_rule(str, "10.0.0.3", 0, 0); // hard code the dst to .3

    /* quit and stop the controller */
    printf("Press Enter to stop the controller and exit\n");
    fgets(str, 64, stdin);
    controller_stop();

    return 0;
}
