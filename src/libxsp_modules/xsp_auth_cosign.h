#ifndef XSP_COSIGN_PASS_H
#define XSP_COSIGN_PASS_H

typedef struct xsp_cosign_user_info_t {
	char *username;
	char *password;
	char *email;
	char *institution;
	char *auth_service;
	char *post_fields;
	int activated;
} xspCosignUserInfo;

xspCosignUserInfo *xsp_alloc_cosign_user_info();
void xsp_free_cosign_user_info(xspCosignUserInfo *ui);

#endif
