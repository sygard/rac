#ifndef _VIEW_MAIN_H
#define _VIEW_MAIN_H

#include "main.h"

enum stats_windows {
	STATS_80211N,
	STATS_80211BG,
	STATS_RATE_CHANGE,
	STATS_SAMPLE,
};

void view_main_setup();
void view_main_exit();
void view_main_update();
void view_main_set_active_station(struct station *stn);
void view_main_set_active_stats_window(enum stats_windows w);

#endif
