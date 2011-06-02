#ifndef LIBXSP_SEC_H
#define LIBXSP_SEC_H

enum xsp_sec {
	XSP_SEC_NONE = 0,
	XSP_SEC_SSH,
	XSP_SEC_SSL
};

typedef struct libxsp_sec_info_t {
        char *username;
        char *password;
        char *key1;
        char *key2;
        char *keypass;
} libxspSecInfo;


#endif
