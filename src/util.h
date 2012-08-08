/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2011 Bruno Randolf (br1@einfach.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <sys/time.h>
#include "list.h"

#ifdef _ALLBSD_SOURCE
#include <machine/endian.h>
#elif __linux__
#include <endian.h>
#endif

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#else
#include <byteswap.h>
#endif

#if DO_DEBUG
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
	#define le64toh(x) (x)
	#define le32toh(x) (x)
	#define le16toh(x) (x)
	#define htole64(x) (x)
	#define htole32(x) (x)
	#define htole16(x) (x)
#else
	#define le64toh(x) bswap_64(x)
	#define le32toh(x) bswap_32(x)
	#define le16toh(x) bswap_16(x)
	#define htole64(x) bswap_64(x)
	#define htole32(x) bswap_32(x)
	#define htole16(x) bswap_16(x)
#endif

void
dump_packet(const unsigned char* buf, int len);

const char*
ether_sprintf(const unsigned char *mac);

const char*
ether_sprintf_short(const unsigned char *mac);

const char*
ip_sprintf(const unsigned int ip);

const char*
ip_sprintf_short(const unsigned int ip);

int
compare_mac(unsigned char* mac1, unsigned char* mac2);

void
convert_string_to_mac(const char* string, unsigned char* mac);

int
normalize(float val, int max_val, int max);

static inline int normalize_db(int val, int max)
{
	if (val <= 30)
		return 0;
	else if (val >= 100)
		return max;
	else
		return normalize(val - 30, 70, max);
}

char
get_packet_type_char(int type);

const char*
get_packet_type_name(int type);

const char*
kilo_mega_ize(unsigned int val);

#define MAC_NOT_EMPTY(_mac) (_mac[0] || _mac[1] || _mac[2] || _mac[3] || _mac[4] || _mac[5])
#define MAC_EMPTY(_mac) (!_mac[0] && !_mac[1] && !_mac[2] && !_mac[3] && !_mac[4] && !_mac[5])

#define MAC_SAME(mac1,mac2) (mac1[0] == mac2[0] && mac1[1] == mac2[1] && mac1[2] == mac2[2] && \
	mac1[3] == mac2[3] && mac1[4] == mac2[4] && mac1[5] == mac2[5])

#define TOGGLE_BIT(_x, _m) (_x) ^= (_m)

#define max(_x, _y) ((_x) > (_y) ? (_x) : (_y))
#define min(_x, _y) ((_x) < (_y) ? (_x) : (_y))

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

static inline __attribute__((const))
int is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

int
ilog2(int x);

void get_relative_time(struct timeval *a, struct timeval *res);

unsigned int list_length(struct list_head *list);

void strtolower(char *str);


int get_80211bg_rate_index(unsigned int rate);

#endif
