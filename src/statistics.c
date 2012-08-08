#include <string.h>
#include <stdlib.h>

#include "list.h"
#include "main.h"

static int prev_seqno_bg = 0;
static int prev_seqno_n = 0;

static int first_bg = 1;
static int first_n  = 1;

static int handle_80211bg(struct station *stn, struct packet_info *p);
static int handle_80211n(struct station *stn, struct packet_info *p);

void
statistics_handle_packet(struct station *stn, struct packet_info *p)
{

}

void
statistics_handle_data_packet(struct station *stn, struct packet_info *p)
{
	stn->received_packets[_DATA]++;
	stn->received_retransmits += p->wlan_retries;
	stn->retransmitted_packets += !!(p->wlan_retries);

	if (p->phy_n) {
		if (handle_80211n(stn,p)) {
			return;
		}
	} else {
		if (handle_80211bg(stn,p)) {
			return;
		}
	}
}

void
statistics_handle_ctrl_packet(struct station *stn, struct packet_info *p)
{
	stn->received_packets[_CTRL]++;

	if (p->pkt_types & PKT_TYPE_RTS) {
		stn->use_rts = 1;
		stn->ctrl_stat.num_rts++;
	}

	if (p->pkt_types & PKT_TYPE_CTS) {
		stn->use_cts = 1;
		stn->ctrl_stat.num_cts++;
	}
}

void
statistics_handle_mgmt_packet(struct station *stn, struct packet_info *p)
{
	stn->received_packets[_MGMT]++;
}

static int
handle_80211bg(struct station *stn, struct packet_info *p)
{
	struct loss *loss;
	unsigned int diff;
	if (first_bg) {
		first_bg = 0;
		prev_seqno_bg = p->wlan_seqno;
		return -1;
	}

	if (prev_seqno_n -1 == p->wlan_seqno || prev_seqno_n == p->wlan_seqno) {
		return -1;
	}

	if (prev_seqno_bg + 1 != p->wlan_seqno) {
		if (prev_seqno_bg > p->wlan_seqno) {
			/* Assume sequence number reset */
			diff = (p->wlan_seqno + 4096) - prev_seqno_bg;
			stn->estimated_lost_packets += diff;
		} else {
			diff = p->wlan_seqno - prev_seqno_bg;
			stn->estimated_lost_packets += diff;
		}
		
		loss = malloc(sizeof(struct loss));
		memcpy(&(loss->time), &(p->received), sizeof(struct timeval));
		loss->num_lost = diff;
		list_add_tail(&(loss->list), &(stn->losses));
	}

	stn->legacy_num_packets[(p->phy_rate * 2) / 1000]++;

	prev_seqno_bg = p->wlan_seqno;

	stn->curr_phy_rate = p->phy_rate;
	stn->curr_phy_freq = p->phy_freq;
	stn->curr_phy_channel = p->phy_chan;

	return 0;
}

static int
handle_80211n(struct station *stn, struct packet_info *p)
{
	struct loss *loss;
	struct packet_info *entry;
	unsigned int diff;
	if (first_n) {
		first_n = 0;
		prev_seqno_n = p->wlan_seqno;
		return -1;
	}

	if (prev_seqno_n -1 == p->wlan_seqno || prev_seqno_n == p->wlan_seqno) {
		return -1;
	}

	if (prev_seqno_n + 1 != p->wlan_seqno) {
		if (prev_seqno_n > p->wlan_seqno) {
			/* Assume sequence number reset */
			diff = (p->wlan_seqno + 4096) - prev_seqno_n;
			stn->estimated_lost_packets += diff;
		} else {
			diff = p->wlan_seqno - prev_seqno_n;
			stn->estimated_lost_packets += diff;
		}
		loss = malloc(sizeof(struct loss));
		memcpy(&(loss->time), &(p->received), sizeof(struct timeval));
		loss->num_lost = diff;
		list_add_tail(&(loss->list), &(stn->losses));
	}

	stn->phy_n = p->phy_n;

	stn->curr_mcs_index = p->mcs.mcs;
	stn->curr_guard_interval = p->mcs.flags_guard_interval;
	stn->curr_bandwidth = p->mcs.flags_bandwidth;

	stn->mcs_num_packets[p->mcs.mcs]
		[PHY80211N_MCS_CALC(p->mcs.flags_bandwidth,
				p->mcs.flags_guard_interval)]++;

	list_for_each_entry(entry, &p->retransmits, retransmits)
		stn->mcs_num_packets[entry->mcs.mcs]
		[PHY80211N_MCS_CALC(entry->mcs.flags_bandwidth,
				entry->mcs.flags_guard_interval)]++;

	prev_seqno_n = p->wlan_seqno;

	stn->curr_phy_rate = p->phy_rate;
	stn->curr_phy_freq = p->phy_freq;
	stn->curr_phy_channel = p->phy_chan;

	return 0;
}
