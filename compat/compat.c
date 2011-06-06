/*
 * There are two different licenses in use by this file.  The first one
 * is the classic 3-clause BSD license: (The old clause 3 has been removed,
 * pursant to ftp://ftp.cs.berkeley.edu/ucb/4bsd/README.Impt.License.Change
 *
 * * * *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. 
 * * * *
 *
 * The second license is OpenBSD's ISC-like license, which is used for 
 * strlcpy() and strlcat().  See the license later on in the file.
 * 
 * Everthing else has had its copyright explicitly disclaimed by the author.
 */

#include "config.h"
#include "compat.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#ifndef JUNOS
#include <net/if.h>
#endif
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/stat.h>


#ifndef HAVE_STRTOUL
/*
 * Copyright (c) 1990 Regents of the University of California.
 * All rights reserved.
 *
 * Licensed under the 3-clause BSD license, see above for text.
 */

/*
 * Convert a string to an unsigned long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
unsigned long strtoul (const char *nptr, char **endptr, int base)
{
	const char *s;
	unsigned long acc, cutoff;
	int c;
	int neg, any, cutlim;

	s = nptr;
	do
		c = *s++;
	while (isspace(c));

	if (c == '-') 
	{
		neg = 1;
		c = *s++;
	} 
	else 
	{
		neg = 0;
		if (c == '+')
			c = *s++;
	}

	if ((base == 0 || base == 16) && c == '0' && (*s == 'x' || *s == 'X')) 
	{
		c = s[1];
		s += 2;
		base = 16;
	}

	if (base == 0)
		base = c == '0' ? 8 : 10;

#ifndef ULONG_MAX
#define ULONG_MAX (unsigned long) -1
#endif

	cutoff = ULONG_MAX / (unsigned long)base;
	cutlim = ULONG_MAX % (unsigned long)base;

	for (acc = 0, any = 0;; c = *s++) 
	{
		if (isdigit(c))
			c -= '0';
		else if (isalpha(c))
			c -= isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;

		if (c >= base)
			break;

		if (any < 0)
			continue;

		if (acc > cutoff || (acc == cutoff && c > cutlim))
		{
			any = -1;
			acc = ULONG_MAX;
			errno = ERANGE;
		}
		else 
		{
			any = 1;
			acc *= (unsigned long)base;
			acc += c;
		}
	}
	if (neg && any > 0)
		acc = -acc;
	if (endptr != 0)
		*endptr = (char *) (any ? s - 1 : nptr);
	return (acc);
}
#endif /* DO NOT HAVE STRTOUL */

#ifndef HAVE_ATOLL
# ifdef HAVE_LONG_LONG
#  ifdef HAVE_STRTOLL
#   define HAVE_ATOLL_REPLACEMENT
long long	atoll (const char *str)
{
	return strtoll(str, NULL, 0);
}
#  else
#   ifdef HAVE_ATOQ
#    define HAVE_ATOLL_REPLACEMENT
long long	atoll (const char *str)
{
	return (long long)atoq(str);
}
#   endif
#  endif
# endif
# ifndef HAVE_ATOLL_REPLACEMENT
#  ifdef HAVE_LONG_LONG
long long	atoll (const char *str)
{
	return (long long)atol(str);
}
#  else
#warning "atoll is simply a wrapper for atol. results may not be exactly as expected"
long long atoll (const char *str)
{
	return (long long) atol(str);
}
#  endif
# endif
#endif

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TODD C. MILLER DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL TODD C. MILLER BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HAVE_STRLCPY
/*	OpenBSD's strlcpy.c version 1.7 2003/04/12 21:56:39 millert */
/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t	strlcpy (char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d = *s) == 0)
				break;
			d++;
			s++;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s)
			s++;
	}

	return(s - src);	/* count does not include NUL */
}
#endif

#ifndef HAVE_STRLCAT
/*      OpenBSD's strlcat.c version 1.10 2003/04/12 21:56:39 millert */
/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t	strlcat (char *dst, const char *src, size_t siz)
{
        char *d = dst;
        const char *s = src;
        size_t n = siz;
        size_t dlen;

        /* Find the end of dst and adjust bytes left but don't go past end */
        while (n-- != 0 && *d != '\0')
                d++;
        dlen = d - dst;
        n = siz - dlen;

        if (n == 0)
                return(dlen + strlen(s));
        while (*s != '\0') {
                if (n != 1) {
                        *d++ = *s;
                        n--;
                }
                s++;
        }
        *d = '\0';

        return(dlen + (s - src));        /* count does not include NUL */
}
#endif

char *bin2hex(const char *src, char *dst, int size) {
	int i;
	char *tmp = dst;

	for(i = 0; i < size; i++) {
		char t = src[i];
		sprintf(tmp, "%X", (t & 0xF0) >> 4);
		tmp++;
		sprintf(tmp, "%X", (t & 0x0F));
		tmp++;
	}

	tmp = '\0';

	return dst;
}

char *hex2bin(const char *src, char *dst, int size) {
	int i;

	if (size % 2 != 0)
		return NULL;

	for(i = 0; i < size; i+=2) {
		char tmp[3];
		int n;

		tmp[0] = src[i];
		tmp[1] = src[i + 1];
		tmp[2] = '\0';

		sscanf(tmp, "%x", &n);

		dst[i/2] = (unsigned char) n;
	}

	return dst;
}

char **split(const char *string, char *delimiters, int *count) {
	char *buf = strdup(string);
	char *token, *save_ptr;
	char **retval;
	char **new_retval;
	int i;

	if (!buf)
		goto error_exit;

	save_ptr = buf;
	retval = NULL;
	i = 0;

	while((token = strtok_r(NULL, delimiters, &save_ptr)) != NULL) {
		new_retval = realloc(retval, sizeof(char *) * (i + 1));
		if (new_retval == NULL)
			goto error_exit2;

		retval = new_retval;

		retval[i] = strdup(token);
		i++;
	}

	*count = i;

	free(buf);

	return retval;

error_exit2:
	if (retval)
		free(retval);
	free(buf);
error_exit:
	*count = 0;
	return NULL;
}

char **split_inline(char *string, char *delimiters, int skip_empty, int *count) {
	char **retval;
	char **new_retval;
	int i, j;
	char *str_start;
	int curr_spot;

	retval = malloc(sizeof(char *));
	if (!retval) {
		goto error_exit;
	}

	curr_spot = 0;

	str_start = string;

	for(i = 0; string[i] != '\0'; i++) {
		for(j = 0; j < strlen(delimiters); j++) {
			if (string[i] == delimiters[j]) {
				string[i] = '\0';

				if (!skip_empty || (skip_empty && strlen(str_start)) > 0) {
					new_retval = realloc(retval, sizeof(char *) * (curr_spot + 1));
					if (new_retval == NULL)
						goto error_exit2;

					retval = new_retval;

					retval[curr_spot] = str_start;

					curr_spot++;
				}

				str_start = string + i + 1;

				break;
			}
		}
	}

	if (!skip_empty || (skip_empty && strlen(str_start) > 0)) {
		new_retval = realloc(retval, sizeof(char *) * (curr_spot + 1));
		if (new_retval == NULL)
			goto error_exit2;

		retval = new_retval;

		retval[curr_spot] = str_start;

		curr_spot++;
	}

	*count = curr_spot;

	return retval;

error_exit2:
	free(retval);
error_exit:
	*count = 0;
	return NULL;
}

double difftv(struct timeval *start, struct timeval *end) {
	double retval;

	retval = end->tv_sec - start->tv_sec;

	if(end->tv_usec >= start->tv_usec) {
		retval += ((double)(end->tv_usec - start->tv_usec)) / 1000000;
	} else {
		retval -= 1.0;
		retval += ((double)(end->tv_usec + 1000000) - start->tv_usec) / 1000000;
	}

	return retval;
}

char *lookup_servername() {
	struct hostent *he;
	char hostname_buf[512];

	if (gethostname(hostname_buf, sizeof(hostname_buf)) == -1)
		goto error_exit;

	he = gethostbyname(hostname_buf);
	if (he == NULL)
		goto error_exit;

	return get_fqdn(he);

error_exit:
	return NULL;
}

char *get_fqdn(struct hostent *he) {
	int i;
	char *fqdn = NULL;

	if(!strchr(he->h_name, '.')) {
		if (he->h_aliases) {
			for(i=0; he->h_aliases[i] != NULL; i++) {
				if (strchr(he->h_aliases[i], '.')) {
					fqdn = strdup(he->h_aliases[i]);
					break;
				}
			}

			if (fqdn == NULL)
				goto error_exit;
		} else {
			goto error_exit;
		}
	} else {
		fqdn = strdup(he->h_name);
	}

	return fqdn;

error_exit:
	return NULL;
}

int daemonize() {
	pid_t pid, sid;

	/* already a daemon */
	if ( getppid() == 1 ) return 0;

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}
	/* If we got a good PID, then we can exit the parent process. */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* At this point we are executing as the child process */

	/* Change the file mode mask */
	umask(0);

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		exit(EXIT_FAILURE);
	}

	signal(SIGHUP, SIG_IGN);

	/* Redirect standard files to /dev/null */
	freopen( "/dev/null", "r", stdin);
	freopen( "/dev/null", "w", stdout);
	freopen( "/dev/null", "w", stderr);

	return 0;
}

int strlist_add(const char *str, char ***list, int *list_length) {
	char **new_list;
	char *new_str;

	new_str = strdup(str);
	if (!new_str)
		goto error_exit;

	new_list = realloc(*list, sizeof(char *) * (*list_length + 1));
	if (new_list == NULL)
		goto error_exit2;

	new_list[*list_length] = new_str;

	*list = new_list;
	*list_length = *list_length + 1;

	return 0;

error_exit2:
	free(new_str);
error_exit:
	return -1;
}

void strlist_free(char **list, int list_length) {
	int i;

	for(i = 0; i < list_length; i++)
		free(list[i]);
	free(list);
}

#if !defined(HAVE_OPENSSL) || defined(USE_COMPAT_SHA)

// Code by: B-Con (http://b-con.us) 
// Released under the GNU GPL 
// MD5 Hash Digest implementation (little endian byte order) 

#include <stdio.h> 
#include <string.h> 

// DBL_INT_ADD treats two unsigned ints a and b as one 64-bit integer and adds c to it
#define ROTLEFT(a,b) ((a << b) | (a >> (32-b))) 
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - c) ++b; a += c; 

void sha1_transform(SHA1_CTX *ctx, const uchar data[]) 
{  
   uint a,b,c,d,e,i,j,t,m[80]; 
      
   for (i=0,j=0; i < 16; ++i, j += 4) 
      m[i] = (data[j] << 24) + (data[j+1] << 16) + (data[j+2] << 8) + (data[j+3]); 
   for ( ; i < 80; ++i) { 
      m[i] = (m[i-3] ^ m[i-8] ^ m[i-14] ^ m[i-16]); 
      m[i] = (m[i] << 1) | (m[i] >> 31); 
   }  
   
   a = ctx->state[0]; 
   b = ctx->state[1]; 
   c = ctx->state[2]; 
   d = ctx->state[3]; 
   e = ctx->state[4]; 
   
   for (i=0; i < 20; ++i) { 
      t = ROTLEFT(a,5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i]; 
      e = d; 
      d = c; 
      c = ROTLEFT(b,30); 
      b = a; 
      a = t; 
   }  
   for ( ; i < 40; ++i) { 
      t = ROTLEFT(a,5) + (b ^ c ^ d) + e + ctx->k[1] + m[i]; 
      e = d; 
      d = c; 
      c = ROTLEFT(b,30); 
      b = a; 
      a = t; 
   }  
   for ( ; i < 60; ++i) { 
      t = ROTLEFT(a,5) + ((b & c) ^ (b & d) ^ (c & d))  + e + ctx->k[2] + m[i]; 
      e = d; 
      d = c; 
      c = ROTLEFT(b,30); 
      b = a; 
      a = t; 
   }  
   for ( ; i < 80; ++i) { 
      t = ROTLEFT(a,5) + (b ^ c ^ d) + e + ctx->k[3] + m[i]; 
      e = d; 
      d = c; 
      c = ROTLEFT(b,30); 
      b = a; 
      a = t; 
   }  
   
   ctx->state[0] += a; 
   ctx->state[1] += b; 
   ctx->state[2] += c; 
   ctx->state[3] += d; 
   ctx->state[4] += e; 
}  

void sha1_init(SHA1_CTX *ctx) 
{  
   ctx->datalen = 0; 
   ctx->bitlen[0] = 0; 
   ctx->bitlen[1] = 0; 
   ctx->state[0] = 0x67452301; 
   ctx->state[1] = 0xEFCDAB89; 
   ctx->state[2] = 0x98BADCFE; 
   ctx->state[3] = 0x10325476; 
   ctx->state[4] = 0xc3d2e1f0; 
   ctx->k[0] = 0x5a827999; 
   ctx->k[1] = 0x6ed9eba1; 
   ctx->k[2] = 0x8f1bbcdc; 
   ctx->k[3] = 0xca62c1d6; 
}  

void sha1_update(SHA1_CTX *ctx, const uchar data[], uint len) 
{  
   uint t,i;
   
   for (i=0; i < len; ++i) { 
      ctx->data[ctx->datalen] = data[i]; 
      ctx->datalen++; 
      if (ctx->datalen == 64) { 
         sha1_transform(ctx,ctx->data); 
         DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],512); 
         ctx->datalen = 0; 
      }  
   }  
}  

void sha1_final(SHA1_CTX *ctx, uchar hash[]) 
{  
   uint i; 
   
   i = ctx->datalen; 
   
   // Pad whatever data is left in the buffer. 
   if (ctx->datalen < 56) { 
      ctx->data[i++] = 0x80; 
      while (i < 56) 
         ctx->data[i++] = 0x00; 
   }  
   else { 
      ctx->data[i++] = 0x80; 
      while (i < 64) 
         ctx->data[i++] = 0x00; 
      sha1_transform(ctx,ctx->data); 
      bzero(ctx->data,56); 
   }  
   
   // Append to the padding the total message's length in bits and transform. 
   DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],8 * ctx->datalen); 
   ctx->data[63] = ctx->bitlen[0]; 
   ctx->data[62] = ctx->bitlen[0] >> 8; 
   ctx->data[61] = ctx->bitlen[0] >> 16; 
   ctx->data[60] = ctx->bitlen[0] >> 24; 
   ctx->data[59] = ctx->bitlen[1]; 
   ctx->data[58] = ctx->bitlen[1] >> 8; 
   ctx->data[57] = ctx->bitlen[1] >> 16;  
   ctx->data[56] = ctx->bitlen[1] >> 24; 
   sha1_transform(ctx,ctx->data); 
   
   // Since this implementation uses little endian byte ordering and MD uses big endian, 
   // reverse all the bytes when copying the final state to the output hash. 
   for (i=0; i < 4; ++i) { 
      hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff; 
      hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff; 
      hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff; 
      hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff; 
      hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff; 
   }  
}  

void SHA1(const uchar *buf, unsigned long length, uchar *hash) {
   SHA1_CTX ctx; 

   sha1_init(&ctx); 
   sha1_update(&ctx, buf, length); 
   sha1_final(&ctx, hash); 
}

#endif

#ifndef JUNOS
int get_addrs(char ***addrs, int *addr_count) {
        struct ifaddrs *if_info;
        struct ifaddrs *curr_if;
        char **interfaces = NULL;
        int i, count = 0;

        if (getifaddrs(&if_info) != 0) {
                goto error_exit;
        }

        for(curr_if = if_info; curr_if != NULL; curr_if = curr_if->ifa_next) {
                char buf[255];
                socklen_t sa_len;
                char **new_interfaces;

                if (!curr_if->ifa_addr)
                        continue;

                if ((curr_if->ifa_flags & IFF_LOOPBACK) || (curr_if->ifa_flags & IFF_POINTOPOINT) || !(curr_if->ifa_flags & IFF_UP))
                        continue;

                if(curr_if->ifa_addr->sa_family != AF_INET && curr_if->ifa_addr->sa_family != AF_INET6)
                        continue;

                if (curr_if->ifa_addr->sa_family == AF_INET)
                        sa_len = sizeof (struct sockaddr_in);
                else
                        sa_len = sizeof (struct sockaddr_in6);

                if (getnameinfo (curr_if->ifa_addr, sa_len, buf, sizeof (buf), NULL, 0, NI_NUMERICHOST) < 0) {
                        perror ("getnameinfo");
                        continue;
                }

                new_interfaces = realloc(interfaces, sizeof(char *) * (count + 1));
                if (!new_interfaces) {
                        goto error_exit2;
                }

                new_interfaces[count] = strdup(buf);
                if (!new_interfaces[count]) {
                        goto error_exit2;
                }

                count += 1;

                interfaces = new_interfaces;
        }

        freeifaddrs(if_info);

        *addrs = interfaces;
        *addr_count = count;

        return 0;

error_exit2:
        for(i = 0; i < count; i++) {
                free(interfaces[i]);
        }
        free(interfaces);
        freeifaddrs(if_info);
error_exit:
        return -1;
}
#endif // JUNOS

int *listen_port_iface(char **interfaces, int interface_count, int protocol, int port, int *length) {
	int *sd_list;
	int sd_count;
	int i;
	int sd;

	sd_list = NULL;
	sd_count = 0;

	for(i = 0; i < interface_count; i++) {
		struct hostent *he;
		struct sockaddr_storage sa;
		int *new_sd_list;

		sd = socket(AF_INET, SOCK_STREAM, protocol);
		if (!sd) {
			printf("failed to get the socket\n");
			goto error_exit;
		}

		he = gethostbyname(interfaces[i]);
		if (he != NULL) {
			bzero((void *)&sa, sizeof(struct sockaddr_storage));
			((struct sockaddr *)&sa)->sa_family = he->h_addrtype;
			if (he->h_addrtype == AF_INET) {
				memcpy (&(((struct sockaddr_in *) &sa)->sin_addr), he->h_addr_list[0], he->h_length);
				((struct sockaddr_in *) &sa)->sin_port = htons(port);
			} else {
				memcpy (&(((struct sockaddr_in6 *) &sa)->sin6_addr), he->h_addr_list[0], he->h_length);
				((struct sockaddr_in6 *) &sa)->sin6_port = htons(port);
			}
		} else {
			goto error_exit2;
		}

		if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
			goto error_exit2;
		}

		if (listen(sd, 32) < 0) {
			goto error_exit2;
		}

		new_sd_list = realloc(sd_list, sizeof(int) * (sd_count + 1));
		if (!new_sd_list) {
			goto error_exit2;
		}

		new_sd_list[sd_count] = sd;
		sd_list = new_sd_list;
		sd_count++;
	}

	*length = sd_count;

	return sd_list;

error_exit2:
	close(sd);
error_exit:
	if (sd_list != NULL)
		free(sd_list);
	return NULL;
}

int *listen_port(int protocol, int family, int port, int *length, struct addrinfo **ret_addrs) {
	struct addrinfo hints;
	struct addrinfo *srv_addrs, *srv;
	int on = 1;
	char sport[10];
	int error;
	int srv_addrs_size;
	int *ret_sockets;
	int num_sockets;
	struct addrinfo *unused_addrs, *used_addrs, *next_addr;
	struct addrinfo *used_addr_tail;

	bzero(&hints, sizeof(struct addrinfo));

	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_PASSIVE;

	snprintf(sport, sizeof(sport), "%d", port);

	error = getaddrinfo(NULL, sport, &hints, &srv_addrs);
	if (error != 0)
		goto error_exit;

	srv_addrs_size = 0;

	for(srv = srv_addrs; srv != NULL; srv = srv->ai_next)
		srv_addrs_size++;

	ret_sockets = (int *) malloc(srv_addrs_size * sizeof(int));
	if (!ret_sockets)
		goto error_exit2;


	num_sockets = 0;

	unused_addrs = NULL;
	used_addrs = NULL;
	used_addr_tail = NULL;


	for(srv = srv_addrs; srv != NULL; srv = next_addr) {

		next_addr = srv->ai_next;

		ret_sockets[num_sockets] = socket(srv->ai_family, srv->ai_socktype, srv->ai_protocol);
		if (ret_sockets[num_sockets] < 0) {
			srv->ai_next = unused_addrs;
			unused_addrs = srv;
			continue;
		}

		setsockopt(ret_sockets[num_sockets], SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof on);

		if (bind(ret_sockets[num_sockets], srv->ai_addr, srv->ai_addrlen) < 0) {
			close(ret_sockets[num_sockets]);
			srv->ai_next = unused_addrs;
			unused_addrs = srv;
			continue;
		}

		if (listen(ret_sockets[num_sockets], 32) < 0) {
			close(ret_sockets[num_sockets]);
			srv->ai_next = unused_addrs;
			unused_addrs = srv;
			continue;
		}

		if (used_addr_tail != NULL) {
			used_addr_tail->ai_next = srv;
		} else {
			used_addr_tail = srv;
			used_addrs = srv;
		}

		srv->ai_next = NULL;

		// we've got a listening socket, 
		num_sockets++;
	}

	srv_addrs = NULL;

	if (num_sockets == 0)
		goto error_exit3;

	*length = num_sockets;

	if (unused_addrs)
		freeaddrinfo(unused_addrs);

	if (ret_addrs == NULL)
		freeaddrinfo(used_addrs);
	else
		*ret_addrs = used_addrs;

	return ret_sockets;

error_exit3:
	free(ret_sockets);

	if (unused_addrs)
		freeaddrinfo(unused_addrs);

	if (used_addrs)
		freeaddrinfo(used_addrs);
error_exit2:
	if (srv_addrs)
		freeaddrinfo(srv_addrs);
error_exit:
	return NULL;
}

#ifndef htonll
uint64_t htonll(uint64_t val) {
	uint32_t a = INT_MAX;

	// check if we're in big endian or little endian mode
	if (a == htonl(a)) {
		return val;
	} else {
		return (((uint64_t) htonl(val)) << 32) + htonl(val >> 32);
	}
}

uint64_t ntohll(uint64_t val) {
	uint32_t a = INT_MAX;

	// check if we're in big endian or little endian mode
	if (a == htonl(a)) {
		return val;
	} else {
		return (((uint64_t) ntohl(val)) << 32) + ntohl(val >> 32);
	}
}
#endif

int get_ips(char ***ret_ips, int *ret_ip_count) {
	struct ifaddrs *ifaces, *curr;
	char **ips;
	int ip_count;

	if (getifaddrs(&ifaces) != 0) {
		fprintf(stderr, "Failed to get interfaces for host\n");
		return -1;
	}

	ips = NULL;
	ip_count = 0;

	for(curr = ifaces; curr != NULL; curr = curr->ifa_next) {
		char ip[255];
		size_t salen;

		if (!curr->ifa_addr)
			continue;

		if (curr->ifa_addr->sa_family == AF_INET)
			salen = sizeof (struct sockaddr_in);
		else if (curr->ifa_addr->sa_family == AF_INET6)
			salen = sizeof (struct sockaddr_in6);
		else
			continue;


		if (getnameinfo (curr->ifa_addr, salen, ip, sizeof (ip), NULL, 0, NI_NUMERICHOST) < 0) {
			continue;
		}

		if (strlist_add(ip, &ips, &ip_count) != 0) {
			continue;
		}
	}

	*ret_ips = ips;
	*ret_ip_count = ip_count;

	return 0;
}

int strlfcat(char *buf, int buflen, const char *fmt, ...) {
	char *str;
	va_list argp;
	int n;

	va_start(argp, fmt);
	n = vasprintf(&str, fmt, argp);
	va_end(argp);

	if (n < 0) {
		return -1;
	}

	n = strlcat(buf, str, buflen);

	free(str);

	return n;
}

int parse_uri(const char *uri, char **protocol, char **address, int *port) {
	char tmp[255];
	const char *c;
	int i;


	c = uri;

	// read the protocol
	i = 0;
	while(*c != ':') {
		tmp[i] = *c;

		i++;
		c++;
	}
	tmp[i] = '\0';

	if (strcmp(tmp, "") == 0) {
		goto error_exit;
	}

	*protocol = strdup(tmp);

	c++;
	if (*c != '/') {
		goto error_exit_proto;
	}
	c++;
	if (*c != '/') {
		goto error_exit_proto;
	}

	// read the ip
	i = 0; 
	c++;
	if (*c == '[') {
		// IPv6 address
		c++;
		while(*c != ']') {
			tmp[i] = *c;
			i++;
			c++;
		}

		if (*c != ':' && *c != '\0') {
			goto error_exit_proto;
		}
	} else {
		// something else
		while(*c != ':' && *c != '\0') {
			tmp[i] = *c;
			i++;
			c++;
		}
	}

	tmp[i] = '\0';

	if (strcmp(tmp, "") == 0) {
		goto error_exit_proto;
	}

	*address = strdup(tmp);

	if (*c == ':') {
		char *eptr;
		// read the port
		i = 0; 
		c++;
		while(*c != '\0') {
			tmp[i] = *c;
			i++;
			c++;
		}
		tmp[i] = '\0';

		if (strcmp(tmp, "") == 0) {
			goto error_exit_addr;
		}

		*port = strtol(tmp, &eptr, 0);
		if (*port == 0 && errno != 0) {
			goto error_exit_addr;
		}

		if ((*port == LONG_MAX || *port == LONG_MIN) && errno == ERANGE) {
			goto error_exit_addr;
		}

		if (*eptr != '\0') {
			goto error_exit_addr;
		}
	}

	return 0;

error_exit_addr:
	free(*address);
error_exit_proto:
	free(*protocol);
error_exit:
	return -1;
}

int send_email(const char *sendmail_binary, const char *email_address, const char *subject, const char *body) {
	FILE *fptr;
	char sendmail_cmd[1024];

	snprintf(sendmail_cmd, sizeof(sendmail_cmd), "%s -t %s ", sendmail_binary, email_address);
	fptr = popen(sendmail_cmd, "w");
	if (!fptr) {
		goto error_exit;
	}

	fprintf(fptr, "Subject: %s\n", subject);
	fprintf(fptr, "\n");
	fprintf(fptr, "%s\n", body);
	fprintf(fptr, ".\n");

	if (pclose(fptr)) {
		goto error_exit;
	}

	return 0;

error_exit:
	return -1;
}
