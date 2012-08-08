#ifndef _PARSER_H_
#define _PARSER_H_

#include <stdint.h>
#include "main.h"



struct ieee_channel {
	uint16_t frequency;
	uint16_t flags;
};

int parse_radiotap_header(void *buf, int len, struct packet_info *p);
int parse_80211_header(const u_char* buf, int len, struct packet_info* p);




#endif
