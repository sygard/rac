#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ncurses.h>

#include "view_main.h"
#include "main.h"


static WINDOW *status_window = NULL;
static WINDOW *phy_window = NULL;
static WINDOW *rate_stats_window_n = NULL;
static WINDOW *rate_stats_window_bg = NULL;
static WINDOW *rate_stats_change = NULL;
static WINDOW *sample_stats_win = NULL;



static struct station *active_stn;

static struct timeval next_update;
static struct timeval update_frequency;

static struct timeval next_rate_stats_update;
static struct timeval rate_stats_update_frequency;

static struct timeval next_sample_stats_update;
static struct timeval sample_stats_update_frequency;


WINDOW *create_newwin(int height, int width, int starty, int startx, int frame);
void destroy_win(WINDOW *local_win);

static void init_status_window();
static void init_phy_window();
static void init_rate_stats_window_n();
static void init_rate_stats_window_bg();
static void init_rate_stats_change();
static void init_sample_stats();

static void update_status_window();
static void update_phy_window();
static void update_rate_stats_window_n();
static void update_rate_stats_window_bg();
static void update_rate_stats_change();
static void update_sample_stats();

static enum stats_windows current_stats_window;


void
view_main_setup()
{
	initscr();

	if (COLS < 80 || LINES < 40) {
		fprintf(stderr, "The minimum required screen size is 80 columns by 40 rows.\n");
		fprintf(stderr, "You currenly have %dx%d\n", COLS, LINES);
		exit(1);
	}

	raw();
	cbreak();
	timeout(0);
	keypad(stdscr, TRUE);
	noecho();
	curs_set(0);
	
	mvprintw(0,0,"Press q to exit");
	mvprintw(1,0,"Press F2 to get 802.11bg stats");
	mvprintw(2,0,"Press F3 to get 802.11n stats");
	mvprintw(3,0,"Press F4 to get rate change stats");
	mvprintw(4,0,"Press F5 to get sampling stats");
	refresh();
	status_window = newwin(3, COLS, LINES - 3, 0);
	phy_window = newwin(5, 40, LINES - 8, 0);

	update_frequency.tv_sec = 0;
	update_frequency.tv_usec = DISPLAY_UPDATE_INTERVAL;

	rate_stats_update_frequency.tv_sec = 1;
	rate_stats_update_frequency.tv_usec = 0;

	sample_stats_update_frequency.tv_sec = 0;
	sample_stats_update_frequency.tv_usec = 50000;

	init_status_window();
	init_phy_window();

	view_main_set_active_stats_window(STATS_80211BG);

	gettimeofday(&next_update, NULL);
	gettimeofday(&next_rate_stats_update, NULL);
}

void
view_main_exit()
{

	endwin();
}

void
view_main_set_active_station(struct station *stn)
{
	active_stn = stn;
}

void
view_main_set_active_stats_window(enum stats_windows w)
{
	current_stats_window = w;
	switch (current_stats_window) {
	case STATS_80211N: init_rate_stats_window_n(); break;
	case STATS_80211BG: init_rate_stats_window_bg(); break;	
	case STATS_RATE_CHANGE: init_rate_stats_change(); break;
	case STATS_SAMPLE: init_sample_stats(); break;
	}
}

void
view_main_update()
{
	static struct timeval now;
	gettimeofday(&now, NULL);

	int n = getch();
	if (n == KEY_F(1)) {
		exit(0);
	} else if (n == KEY_F(2)) {
		view_main_set_active_stats_window(STATS_80211BG);
	} else if (n == KEY_F(3)) {
		view_main_set_active_stats_window(STATS_80211N);
	} else if (n == KEY_F(4)) {
		view_main_set_active_stats_window(STATS_RATE_CHANGE);
	} else if (n == KEY_F(5)) {
		view_main_set_active_stats_window(STATS_SAMPLE);
	} else if (n == 'q') {
		exit(0);
	}
	
	if (timercmp(&now, &next_update, <))
		return;

	update_status_window();
	update_phy_window();

	switch (current_stats_window) {
	case STATS_80211N: update_rate_stats_window_n(); break;
	case STATS_80211BG: update_rate_stats_window_bg(); break;
	case STATS_RATE_CHANGE: update_rate_stats_change(); break;
	case STATS_SAMPLE: update_sample_stats(); break;
	}
	timeradd(&now, &update_frequency, &next_update);
}

static void
init_status_window()
{
	whline(status_window, '-', COLS);
}

static void
init_phy_window()
{
	
}

static void
init_rate_stats_window_n()
{
	if (!rate_stats_window_n) 
		rate_stats_window_n = newwin(LINES - 3, COLS - 40, 0, 40);
	
	wclear(rate_stats_window_n);
	box(rate_stats_window_n, 0 , 0);
}

static void
init_rate_stats_window_bg()
{
	if (!rate_stats_window_bg) 
		rate_stats_window_bg = newwin(LINES - 3, COLS - 40, 0, 40);
	
	wclear(rate_stats_window_bg);
	box(rate_stats_window_bg, 0 , 0);
}

static void
init_rate_stats_change() {
	if (!rate_stats_change)
		rate_stats_change = newwin(LINES - 3, COLS - 40, 0, 40);

	wclear(rate_stats_change);
	box(rate_stats_change, 0, 0);

}

static void
init_sample_stats() {
	if (!sample_stats_win)
		sample_stats_win = newwin(LINES - 3, COLS - 40, 0, 40);

	wclear(sample_stats_win);
	box(sample_stats_win, 0, 0);

}


static void
update_status_window()
{
	mvwprintw(status_window, 1,0,  "Captured: %10d",
		active_stn->received_packets[_DATA]
	);
	mvwprintw(status_window, 2,0,  "Lost:  %13d", active_stn->estimated_lost_packets);
	mvwprintw(status_window, 1,21, "Retransmits: %7d", active_stn->received_retransmits);
	mvwprintw(status_window, 2,21, "Rate chg.:   %7d", active_stn->rate_change_stat.num_rate_changes);
	mvwprintw(status_window, 1,42, "Num samples: %7d", active_stn->sample_stat.num_samples);
	mvwprintw(status_window, 2,42, "Loss ratio:  %7.1f",
		active_stn->estimated_lost_packets ? 
		(active_stn->estimated_lost_packets / (float)(active_stn->received_packets[_DATA] + active_stn->estimated_lost_packets)) * 100.0: 0);

	wrefresh(status_window);
}

static void update_phy_window()
{
	if (active_stn->phy_n) {
		mvwprintw(phy_window, 0,0, "------- PHY stat (802.11n) --------");
		mvwprintw(phy_window, 1,0, "Current rate:  %.1fMbps (%2d)",
			active_stn->curr_phy_rate / 1000.0,
			active_stn->curr_mcs_index);
		mvwprintw(phy_window, 2,0, "Channel %d (%dMHz) ",
			active_stn->curr_phy_channel,
			active_stn->curr_phy_freq);
		mvwprintw(phy_window, 3,0, "Bandwidth %dMHz",
			active_stn->curr_bandwidth == 1 ? 40 : 20);
		mvwprintw(phy_window, 4,0, "Guard Interval %s",
			active_stn->curr_guard_interval == 0 ? "800ns (Long)" : "400ns (Short)" );
	} else {
		mvwprintw(phy_window, 0,0, "------- PHY stat (802.11bg) -------");
		mvwprintw(phy_window, 1,0, "Current rate:  %.1fMbps",
			active_stn->curr_phy_rate / 1000.0);

		mvwprintw(phy_window, 2,0, "Channel %d (%dMHz)",
			active_stn->curr_phy_channel,
			active_stn->curr_phy_freq);
	}
	
	wrefresh(phy_window);
}

static void
update_rate_stats_window_n()
{
	int i;
	mvwprintw(rate_stats_window_n, 1, 1, "      Rate statistics for 802.11n     ");
	mvwprintw(rate_stats_window_n, 2, 1, " MCS  -- Long GI  --    -- Short GI --");
	mvwprintw(rate_stats_window_n, 3, 1, "Index 20MHz    40MHz    20MHz    40MHz");

	for (i=0; i<32; i++) {
		mvwprintw(rate_stats_window_n, i+4, 2, "%2d %7d %8d %8d %8d",
			i,
			active_stn->mcs_num_packets[i][0],
			active_stn->mcs_num_packets[i][1],
			active_stn->mcs_num_packets[i][2],
			active_stn->mcs_num_packets[i][3]

			);
	}

	wrefresh(rate_stats_window_n);
}

static void
update_rate_stats_window_bg()
{
	int i, tot;
	int r[12] = { 2, 4, 11, 12, 18, 22, 24, 36, 48, 72, 96, 108 };

	tot = 0;
	for (i=0;i<12;i++)
		tot += active_stn->legacy_num_packets[r[i]];

	mvwprintw(rate_stats_window_bg, 1, 1, "      Rate statistics for 802.11bg    ");
	mvwprintw(rate_stats_window_bg, 2, 2, "Mbps   Num Packets   Percent");
	for (i=0; i<12; i++)
		mvwprintw(rate_stats_window_bg, 3 + i, 2, "%4.1f    %10ld     %5.2f", 
			r[i] / 2.0,
			active_stn->legacy_num_packets[r[i]],
			(active_stn->legacy_num_packets[r[i]] /
				(float)tot) * 100.0

		);

	mvwprintw(rate_stats_window_bg, 15, 1, "Total    %10ld",
		tot);

	wrefresh(rate_stats_window_bg);
}

void destroy_win(WINDOW *local_win)
{	
	wborder(local_win, ' ', ' ', ' ',' ',' ',' ',' ',' ');
	wrefresh(local_win);
	delwin(local_win);
}

static void
update_rate_stats_change()
{
	static struct timeval now;
	struct rate_change *entry;
	int i, n;
	char timestr[32];

	gettimeofday(&now, NULL);
	if (timercmp(&now, &next_rate_stats_update, <))
		return;
	
	mvwprintw(rate_stats_change, 1,1, "Rate changes..");
	mvwprintw(rate_stats_change, 2,1, "Uses 9Mbit? %s (%d) - samplerate?",
		active_stn->legacy_num_packets[18] == 0? "no" : "yes",
		active_stn->legacy_num_packets[18]);

	mvwprintw(rate_stats_change, 3,1, "Changes more then one step? ");

	if (active_stn->rate_change_stat.rate_change_over_multiple_steps)
		mvwprintw(rate_stats_change, 3,29, "yes, %d times.",
		active_stn->rate_change_stat.rate_change_over_multiple_steps);
	else
		mvwprintw(rate_stats_change, 3,29, "no - amrr?");

	mvwprintw(rate_stats_change, 4,1, "Maximum changes pr. second %d",
		active_stn->rate_change_stat.max_rate_change_per_sec);

	mvwprintw(rate_stats_change, 5,1, "Rate change type stats");
	mvwprintw(rate_stats_change, 6,4, "Sequential        %6d",
		active_stn->rate_change_stat.
		rate_change_type_stats[CHANGE_TYPE_SEQUENTIAL]);
	mvwprintw(rate_stats_change, 7,4, "Sequential before %6d",
		active_stn->rate_change_stat.
		rate_change_type_stats[CHANGE_TYPE_SEQUENTIAL_BEFORE]);
	mvwprintw(rate_stats_change, 8,4, "Sequential after  %6d",
		active_stn->rate_change_stat.
		rate_change_type_stats[CHANGE_TYPE_SEQUENTIAL_AFTER]);
	mvwprintw(rate_stats_change, 9,4, "Non-Sequential    %6d",
		active_stn->rate_change_stat.
		rate_change_type_stats[CHANGE_TYPE_NON_SEQUENTIAL]);

	mvwprintw(rate_stats_change, 10,1, "Min time between change %10ld.%06ld sec",
		active_stn->rate_change_stat.min_time_between_rate_changes.tv_sec,
		active_stn->rate_change_stat.min_time_between_rate_changes.tv_usec);
	mvwprintw(rate_stats_change, 11,1, "Min pkt between change  %10d",
		active_stn->rate_change_stat.min_pkt_between_rate_changes);

	struct tm *tm;

	i = 0;
	list_for_each_entry_reverse(entry, &(active_stn->rate_changes), list) {
		if (i >= 10) break;
		tm = localtime(&entry->time.tv_sec);
		
		n = strftime(timestr, 32, "%H:%M:%S", tm);
		n += snprintf(&timestr[n], 32 - n, ".%06ld", entry->time.tv_usec);

		mvwprintw(rate_stats_change, LINES - (5 + i++), 1,
			"%s %4d %6d %6d", timestr, entry->wlan_seqno,
			entry->new_rate, entry->stn_received_ct);
	}

	mvwprintw(rate_stats_change, LINES - (5 + i), 1,
			"-----time--------seq---rate----num");

	wrefresh(rate_stats_change);

	timeradd(&now, &rate_stats_update_frequency, &next_rate_stats_update);
}


static void
update_sample_stats()
{
	struct sample_freq *entry;
	int i;
	struct timeval now;

	wrefresh(sample_stats_win);

	gettimeofday(&now, NULL);
	if (timercmp(&now, &next_sample_stats_update, <))
		return;

	mvwprintw(sample_stats_win, 1,1, "Sampling statistics..");
	mvwprintw(sample_stats_win, 2,1, "Sampling ratio : %.2f", 
		active_stn->sample_stat.num_samples == 0 ? 0.0 :
		(active_stn->sample_stat.num_samples / (float)(active_stn->sample_stat.num_samples + active_stn->received_packets[_DATA])) * 100.0);
	mvwprintw(sample_stats_win, 3,1, "Min frames between samples %d",
		active_stn->sample_stat.min_frames_between_samples);


	i = 0;
	list_for_each_entry(entry, &(active_stn->sample_stat.sampling_frequency), list) {
		mvwprintw(sample_stats_win, LINES - (5 + (10 - i++)), 1, "%3d %8d",
			entry->since_last,
			entry->num_samples);
		if (i > 10) break;
	}

	for (i=0;i<10;i++) {
		mvwprintw(sample_stats_win, LINES - (5 + (10 - i)), 20, "%3d - %3d : %d",
			(i*10), ((i*10)+9), active_stn->sample_stat.num_samples_range[i]);
	}

	timeradd(&now, &sample_stats_update_frequency, &next_sample_stats_update);
}

