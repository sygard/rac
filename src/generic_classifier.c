#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "main.h"
#include "list.h"
#include "util.h"

#define IS_SAMPLE(a,b,c) ((a->wlan_seqno - 1 == b->wlan_seqno && b->wlan_seqno - 1 == c->wlan_seqno) \
	&& (a->phy_rate == c->phy_rate && a->phy_rate != b->phy_rate))

static void analyse_rate_change(struct station *stn);
static void analyse_retries(struct station *stn);
static void analyse_samples(struct station *stn);

static void do_rate_change_statistics(struct station *stn);
static void do_sampling_statistics(struct station *stn);

void
generic_classifier(struct station *stn, struct packet_info *p)
{
	struct packet_info *entry, *tmp;

	/* Throw away unwanted frames */
	if (p->pkt_types & PKT_TYPE_NULL) return;

	/* Free all memory used by the oldest frame pointer */
	if (stn->e) {
		list_for_each_entry_safe(entry, tmp, &(stn->e->retransmits), retransmits)
			free(entry);
		free(stn->e);
	}

	stn->e = stn->d;
	stn->d = stn->c;
	stn->c = stn->b;
	stn->b = stn->a;
	stn->a = malloc(sizeof(struct packet_info));
	memcpy(stn->a, p, sizeof(struct packet_info));
	INIT_LIST_HEAD(&(stn->a->retransmits));

	list_for_each_entry(entry, &p->retransmits, retransmits) {
		tmp = malloc(sizeof(struct packet_info));
		memcpy(tmp, entry, sizeof(struct packet_info));
		list_add_tail(&(tmp->retransmits), &(stn->a->retransmits));
	}

	if (stn->a == NULL || stn->b == NULL || stn->c == NULL
	   || stn->d == NULL || stn->e == NULL) {
		if (stn->c != NULL)
			stn->current_best_rate = stn->c->phy_rate;
		return;
	}

	analyse_retries(stn);

	if (stn->c->phy_rate == stn->current_best_rate) {
		/* Nothing to do here... */
	} else {
		/* Packet can be a sample, or the result of a 
		 * rate change. */
		if (stn->d->phy_rate == stn->b->phy_rate) {
			/* Probably a sample */
#ifdef DEBUGPKT
			fprintf(stderr, "Sampling... %d %d %d\n",
				stn->d->wlan_seqno, stn->c->wlan_seqno,
				stn->b->wlan_seqno);
#endif
			analyse_samples(stn);
		} else if (stn->c->phy_rate == stn->b->phy_rate) {
#ifdef DEBUGPKT
			fprintf(stderr, "rate change... %d %d %d\n",
				stn->d->wlan_seqno, stn->c->wlan_seqno,
				stn->b->wlan_seqno
);
#endif
			analyse_rate_change(stn);
		} else {
			/* Special case */
#ifdef DEBUGPKT
			fprintf(stderr, "Special case...\n");
#endif


		}
	}



	do_rate_change_statistics(stn);
	do_sampling_statistics(stn);
}

static void
analyse_rate_change(struct station *stn)
{
	struct rate_change *rc;

	rc = malloc(sizeof(struct rate_change));
	memcpy(&rc->time, &stn->c->received, sizeof(struct timeval));

	if (stn->b->wlan_seqno -1 == stn->c->wlan_seqno &&
	   stn->c->wlan_seqno -1 == stn->d->wlan_seqno)
		rc->change_type = CHANGE_TYPE_SEQUENTIAL;
	else if (stn->b->wlan_seqno -1 == stn->c->wlan_seqno)
		rc->change_type = CHANGE_TYPE_SEQUENTIAL_AFTER;
	else if (stn->c->wlan_seqno -1 == stn->d->wlan_seqno)
		rc->change_type = CHANGE_TYPE_SEQUENTIAL_BEFORE;
	else
		rc->change_type = CHANGE_TYPE_NON_SEQUENTIAL;

	rc->new_rate = stn->c->phy_rate;
	rc->wlan_seqno = stn->c->wlan_seqno;
	rc->stn_received_ct = stn->received_packets[_DATA];

	list_add_tail(&rc->list, &stn->rate_changes);
	stn->rate_change_stat.num_rate_changes++;

	stn->current_best_rate = stn->c->phy_rate;
}

static void
analyse_retries(struct station *stn)
{
	struct packet_info *entry;
	struct retry *new;
	int i;

	if (!stn->c->wlan_retries)
		return;

	if (stn->retry_stat.max_num_retries < stn->c->wlan_retries)
		stn->retry_stat.max_num_retries = stn->c->wlan_retries;

	new = malloc(sizeof(struct retry));
	new->num_retries = stn->c->wlan_retries;
	new->original_rate = stn->c->phy_rate;
	new->wlan_seqno = stn->c->wlan_seqno;

	memcpy(&new->time, &stn->c->received, sizeof(struct timeval));

	i = 0;
	list_for_each_entry(entry, &stn->c->retransmits, retransmits) {
		new->retry_chain[i++] = entry->phy_rate;
	}

	list_add_tail(&(new->list), &(stn->retry_stat.retries));
}


static void
analyse_samples(struct station *stn)
{
	struct sample *spl;

	spl = malloc(sizeof(struct sample));
	spl->wlan_seqno = stn->c->wlan_seqno;
	spl->sample_to = stn->c->phy_rate;
	spl->sample_from = stn->c->phy_rate;
	spl->stn_received_ct = stn->received_packets[_DATA];

	memcpy(&spl->time, &stn->c->received, sizeof(struct timeval));

	list_add_tail(&(spl->list), &(stn->samples));
	stn->sample_stat.num_samples++;
	stn->prev_is_sample = 1;
}

static void
do_rate_change_statistics(struct station *stn)
{
	struct rate_change *prev, *curr;
	struct timeval now, next, diff;
	static unsigned int rate_changes_this_sec = 0;
	int prev_ri, curr_ri;		/* Rate indexes */

	gettimeofday(&now, NULL);
	
	if (timercmp(&now, &stn->rate_change_stat.next_analysis, <))
		return;

	if (stn->rate_change_stat.last_analyzed_rate_change == NULL) {
		if (list_empty(&(stn->rate_changes))) {
			return;
		}
		stn->rate_change_stat.last_analyzed_rate_change =
			list_first_entry(&(stn->rate_changes), struct rate_change, list);
	}

	prev = stn->rate_change_stat.last_analyzed_rate_change;
	prev_ri = get_80211bg_rate_index(prev->new_rate);

	curr = list_entry(prev->list.next,
		struct rate_change, list);


	list_for_each_entry_from(curr, &(stn->rate_changes), list) {
		curr_ri = get_80211bg_rate_index(curr->new_rate);
		stn->rate_change_stat.rate_change_type_stats[curr->change_type]++;

		if (curr->time.tv_sec != prev->time.tv_sec) {
			/* New second */
			if (rate_changes_this_sec >
				stn->rate_change_stat.max_rate_change_per_sec )
				stn->rate_change_stat.max_rate_change_per_sec =
					rate_changes_this_sec;
			rate_changes_this_sec = 0;
		}

		rate_changes_this_sec++;
		

		/* Check here if the rate change is across multiplie rate
		 * indexes. If so, it most likely is not amrr. */
		if (prev_ri - curr_ri > 1 || prev_ri - curr_ri < -1) {
			stn->rate_change_stat.rate_change_over_multiple_steps++;
#ifdef DEBUGPKT
			fprintf(stderr, "rate ix's : %d -> %d\n", prev_ri, curr_ri);
			fprintf(stderr, "multiple steps: %d -> %d\n", prev->new_rate, curr->new_rate);
#endif
		}
		
		timersub(&curr->time, &prev->time, &diff);

		if (timercmp(&diff, &stn->rate_change_stat.min_time_between_rate_changes, <))
			memcpy(&stn->rate_change_stat.min_time_between_rate_changes,
				&diff, sizeof(struct timeval));


		if (curr->stn_received_ct - prev->stn_received_ct <
			stn->rate_change_stat.min_pkt_between_rate_changes)
			stn->rate_change_stat.min_pkt_between_rate_changes =
				curr->stn_received_ct - prev->stn_received_ct;
		
		prev_ri = curr_ri;
		prev = curr;
	}

	stn->rate_change_stat.last_analyzed_rate_change =
		list_last_entry(&(stn->rate_changes), struct rate_change, list);

	next.tv_sec = 1;
	next.tv_usec = 0;
	timeradd(&now, &next, &stn->rate_change_stat.next_analysis);
	
}

static void
add_sample_to_frequency_stat(struct station *stn, struct sample *prev, struct sample *curr)
{
	int diff;
	struct sample_freq *entry, *tmp;

	diff = curr->wlan_seqno - prev->wlan_seqno;
	if (diff >= 1000 || diff < 0)	/* Don't care */
		return;

	/* Put the sample into the correct bucket */
	stn->sample_stat.num_samples_range[diff/10]++;

	/* Minimum frames between samples */
	if (stn->sample_stat.min_frames_between_samples > diff)
		stn->sample_stat.min_frames_between_samples = diff;

	tmp = NULL;

	list_for_each_entry(entry, &(stn->sample_stat.sampling_frequency), list) {
		if (entry->since_last == diff) {
			tmp = entry;
			break;
		}
	}

	if (tmp == NULL) {
		tmp = malloc(sizeof(struct sample_freq));
		tmp->since_last = diff;
		tmp->num_samples = 1;
	} else {
		list_del(&tmp->list);
		tmp->num_samples += 1;
	}

	if (list_empty(&(stn->sample_stat.sampling_frequency))) {
		list_add(&tmp->list, &stn->sample_stat.sampling_frequency);
		return;
	}


	list_for_each_entry(entry, &(stn->sample_stat.sampling_frequency), list) {
		if (entry->num_samples < tmp->num_samples)
			break;
	}

	list_add_tail(&tmp->list, &entry->list);

}


static void
do_sampling_statistics(struct station *stn)
{
	struct timeval now, next;
	struct sample *prev, *curr;

	gettimeofday(&now, NULL);
	if (timercmp(&now, &stn->sample_stat.next_analysis, <))
		return;

	if (stn->sample_stat.last_analyzed_sample == NULL) {
		if (list_empty(&(stn->samples))) {
			return;
		}
		stn->sample_stat.last_analyzed_sample =
			list_first_entry(&(stn->samples), struct sample, list);
	}

	prev = stn->sample_stat.last_analyzed_sample;

	curr = list_entry(prev->list.next,
		struct sample, list);


	list_for_each_entry_from(curr, &(stn->samples), list) {
		/* How often does it sample */
		/* Minimum frames between samples */
		add_sample_to_frequency_stat(stn, prev, curr);
	}

	stn->sample_stat.last_analyzed_sample =
		list_last_entry(&(stn->samples), struct sample, list);

	next.tv_sec = 0;
	next.tv_usec = 50000;
	timeradd(&now, &next, &stn->sample_stat.next_analysis);
}
