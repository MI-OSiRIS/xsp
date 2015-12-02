#ifndef COMPAT_H
#define COMPAT_H

#include "config.h"

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#ifdef HAVE_MACHINE_ENDIAN_H
#include <machine/endian.h>
#else
#include <endian.h>
#endif

#ifdef HAVE_BYTESWAP_H
#include <byteswap.h>
#else
#ifdef HAVE_LIBKERN_OSBYTEORDER_H
#include <libkern/OSByteOrder.h>
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)
#endif
#endif

#define TRUE 1
#define FALSE 0

#ifndef HAVE_STRTOUL
unsigned long strtoul (const char *nptr, char **endptr, int base);
#endif

#ifndef HAVE_ATOLL
long long atoll (const char *str);
#endif

#ifndef HAVE_STRLCPY
size_t	strlcpy (char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
size_t	strlcat (char *dst, const char *src, size_t siz);
#endif

#ifndef ntohll
#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t ntohll(uint64_t x)
{
	return bswap_64(x);
}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t ntohll(uint64_t x)
{
	return x;
}
#endif
#endif

#ifndef htonll
#define htonll ntohll
#endif

char *bin2hex(const char *src, char *dst, int size);
char *hex2bin(const char *src, char *dst, int size);
char **split(const char *string, char *delimiters, int *count);
char **split_inline(char *string, char *delimiters, int skip_empty, int *count);
double difftv(struct timeval *start, struct timeval *end);
char *lookup_servername();
char *get_fqdn(struct hostent *he);
int daemonize();
int strlist_add(const char *str, char ***list, int *list_length);
void strlist_free(char **list, int list_length);
#ifndef JUNOS
int get_addrs(char ***addrs, int *addr_count);
#endif
int *listen_port(int protocol, int family, int port, int *length, struct addrinfo **ret_addrs);
int *listen_port_iface(char **interfaces, int interface_count, int protocol, int port, int *length);

#if !defined(HAVE_OPENSSL) || defined(USE_COMPAT_SHA)

#define SHA_DIGEST_LENGTH		20

// Signed variables are for wimps 
#define uchar unsigned char 
#define uint unsigned int 
#define u_char unsigned char
#define u_int unsigned int

typedef struct { 
   uchar data[64]; 
   uint datalen; 
   uint bitlen[2]; 
   uint state[5]; 
   uint k[4]; 
} SHA1_CTX; 

void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const uchar data[], uint len);
void sha1_final(SHA1_CTX *ctx, uchar hash[]);
void SHA1_wrapper(const uchar *buf, unsigned long int, uchar *hash);

#endif

#ifndef htonll
uint64_t htonll(uint64_t val);
uint64_t ntohll(uint64_t val);
#endif

int send_email(const char *sendmail_binary, const char *email_address, const char *subject, const char *body);
int get_ips(char ***ret_ips, int *ret_ip_count);
int strlfcat(char *buf, int buflen, const char *fmt, ...);
#endif
