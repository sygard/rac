#include <stdio.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <errno.h>

#include "main.h"
#include "parser.h"
#include "util.h"
#include "radiotap_iter.h"

int mcsindex[32][4] = {
	{  6500,  13500,   7200,  15000},
	{ 13000,  27000,  14400,  30000},
	{ 19500,  40500,  21700,  45000},
	{ 26000,  54000,  28900,  60000},
	{ 39000,  81000,  43300,  90000},
	{ 52000, 108000,  57800, 120000},
	{ 58500, 121500,  65000, 135000},
	{ 65000, 135000,  72200, 150000},
	{ 13000,  27000,  14400,  30000},
	{ 26000,  54000,  28900,  60000},
	{ 39000,  81000,  43300,  90000},
	{ 52000, 108000,  57800, 120000},
	{ 78000, 162000,  86700, 180000},
	{104000, 216000, 115600, 240000},
	{117000, 243000, 130300, 270000},
	{130000, 270000, 144400, 300000},
	{ 19500,  40500,  21700,  45000},
	{ 39000,  81000,  43300,  90000},
	{ 58500, 121500,  65000, 135000},
	{ 78000, 162000,  86700, 180000},
	{117000, 243000, 130000, 270000},
	{156000, 324000, 173300, 360000},
	{175500, 364500, 195000, 405000},
	{195000, 405000, 216700, 450000},
	{ 26000,  54000,  28900,  60000},
	{ 52000, 108000,  57800, 120000},
	{ 78000, 162000,  86700, 180000},
	{104000, 216000, 115600, 240000},
	{156000, 324000, 173300, 360000},
	{208000, 432000, 231100, 480000},
	{234000, 486000, 260000, 540000},
	{260000, 540000, 288900, 600000},
#endif
};

static const struct radiotap_align_size align_size_000000_00[] = {
	[0] = { .align = 1, .size = 4, },
	[52] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
	{
		.oui = 0x000000,
		.subns = 0,
		.n_bits = sizeof(align_size_000000_00),
		.align_size = align_size_000000_00,
	},
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
	.ns = vns_array,
	.n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};

static int
ieee80211_frequency_to_channel(unsigned int freq)
{
	DEBUG("FREQ: %d\n", freq);

	int base;

        if (freq == 2484)
                return 14;
        if (freq < 2484)
                base = 2407;
        else if (freq >= 4910 && freq <= 4980)
                base = 4000;
        else
                base = 5000;
        return (freq - base) / 5;
}

static int
parse_radiotap_namespace(struct ieee80211_radiotap_iterator *iter,
	struct packet_info *p)
{
	struct ieee_80211_radiotap_mcs *mcs;
	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_RATE:
		p->phy_rate = (*(char*)iter->this_arg * 1000) / 2;
		DEBUG("IEEE80211_RADIOTAP_RATE = %d\n", p->phy_rate);
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
		p->phy_freq = le16toh(*(uint16_t*) iter->this_arg);
		p->phy_chan = ieee80211_frequency_to_channel(p->phy_freq);
		DEBUG("IEEE80211_RADIOTAP_CHANNEL %d (%d)\n", p->phy_freq, p->phy_chan);
		break;
	case IEEE80211_RADIOTAP_TSFT:
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		p->phy_signal = *(char*)iter->this_arg;
		DEBUG("IEEE80211_RADIOTAP_DBM_ANTSIGNAL\n");
		break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		p->phy_noise = *(char*)iter->this_arg;
		DEBUG("IEEE80211_RADIOTAP_DBM_ANTNOISE\n");
		break;
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
		p->phy_snr = *(char*)iter->this_arg;
		DEBUG("IEEE80211_RADIOTAP_DB_ANTSIGNAL\n");
		break;
	case IEEE80211_RADIOTAP_MCS:
		mcs = (struct ieee_80211_radiotap_mcs*)iter->this_arg;

		if (!mcs->known_bandwidth || !mcs->known_guard_interval ||
			!mcs->known_mcs_index)
			return 1;

		p->phy_rate = mcsindex[mcs->mcs][
			PHY80211N_MCS_CALC(mcs->flags_bandwidth, mcs->flags_guard_interval)
		];
		
		memcpy(&(p->mcs), iter->this_arg, 3);
		
		p->phy_n = 1;

		DEBUG("IEEE80211_RADIOTAP_MCS\n");
		break;
	default:
		break;
	}
	return 0;
}

int
parse_radiotap_header(void *buf, int len, struct packet_info *p)
{
	struct ieee80211_radiotap_header *hdr = buf;
	struct ieee80211_radiotap_iterator iter;
	int err = ieee80211_radiotap_iterator_init(&iter, buf, len, &vns);
	int i;

	if (err) {
		printf("malformed radiotap header (init returns %d)\n", err);
		return -1;
	}

	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
			printf("\tvendor NS (%.2x-%.2x-%.2x:%d, %d bytes)\n",
				iter.this_arg[0], iter.this_arg[1],
				iter.this_arg[2], iter.this_arg[3],
				iter.this_arg_size - 6);
			for (i = 6; i < iter.this_arg_size; i++) {
				if (i % 8 == 6)
					printf("\t\t");
				else
					printf(" ");
				printf("%.2x", iter.this_arg[i]);
			}
			printf("\n");
		} else if (iter.is_radiotap_ns) {
			if (parse_radiotap_namespace(&iter, p)) {
				return -1;
			}
		} else {
			fprintf(stderr, "parsed something...\n");
		}

	}

	if (err != -ENOENT) {
		printf("malformed radiotap data\n");
		return -1;
	}

	return hdr->it_len;
}


