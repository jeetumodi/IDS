#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#define MAX_LINES   200
#define LINE_LEN    256
#define W_TIME       8
#define W_CMD       16
#define W_TYPE       7

#define CP_BASE      1
#define CP_ALERT     2
#define CP_RULE      3
#define CP_OPEN      4
#define CP_PTRACE    5
#define CP_CMD       6
#define CP_DIM       7
#define CP_HEADER    8
#define CP_STAT_A    9
#define CP_STAT_R   10
#define CP_STAT_O   11
#define CP_STAT_T   12
#define CP_FILTER   13

#define F_ALL    0
#define F_ALERT  1
#define F_RULE   2
#define F_OPEN   3
#define F_EXEC   4
#define F_PTRACE 5
#define F_COUNT  6

static const char *filter_names[F_COUNT] = {
    "ALL","ALERT","RULE","FILE","EXEC","PTRACE"
};

typedef struct {
    char time[W_TIME + 1];
    char cmd [W_CMD  + 1];
    char type[W_TYPE + 1];
    char msg [LINE_LEN];
    int  cpair;
} Entry;

static Entry           entries[MAX_LINES];
static int             filtered[MAX_LINES];
static int             filtered_count = 0;
static int             total          = 0;
static int             scroll_top     = 0;
static int             filter_mode    = F_ALL;
static int             cnt_alert      = 0;
static int             cnt_rule       = 0;
static int             cnt_open       = 0;
static volatile int    need_resize    = 0;

static void handle_resize(int sig)
{
    (void)sig;
    need_resize = 1;
}

/* ------------------------------------------------------------------ */
static void parse_line(const char *raw, Entry *e)
{
    const char *p = raw;
    const char *end;
    char       *tok;
    char        tmp[LINE_LEN];
    int         parsed = 0;

    memset(e, 0, sizeof(*e));

    {
        time_t     now = time(NULL);
        struct tm *tm  = localtime(&now);
        strftime(e->time, sizeof(e->time), "%H:%M:%S", tm);
    }

    /* Current kernel format: [time] [comm] TYPE details... */
    if (*p == '[') {
        p++;
        end = strchr(p, ']');
        if (end) {
            int len = (int)(end - p);
            if (len > W_TIME)
                len = W_TIME;
            if (len > 0)
                strncpy(e->time, p, len);

            p = end + 1;
            while (*p == ' ')
                p++;

            if (*p == '[') {
                char comm[LINE_LEN];
                char *cs;
                char *ce;

                p++;
                end = strchr(p, ']');
                if (end) {
                    int clen = (int)(end - p);
                    if (clen >= LINE_LEN)
                        clen = LINE_LEN - 1;
                    strncpy(comm, p, clen);

                    cs = comm;
                    while (*cs == ' ')
                        cs++;
                    ce = comm + strlen(comm);
                    while (ce > cs && ce[-1] == ' ')
                        *--ce = '\0';

                    if (*cs)
                        strncpy(e->cmd, cs, W_CMD);
                    else
                        strncpy(e->cmd, "kernel", W_CMD);

                    p = end + 1;
                    while (*p == ' ')
                        p++;

                    if (*p) {
                        const char *tend = p;
                        int tlen;
                        while (*tend && *tend != ' ')
                            tend++;
                        tlen = (int)(tend - p);
                        if (tlen >= (int)sizeof(e->type))
                            tlen = (int)sizeof(e->type) - 1;
                        strncpy(e->type, p, tlen);

                        p = tend;
                        while (*p == ' ')
                            p++;
                        strncpy(e->msg, p, LINE_LEN - 1);
                        parsed = 1;
                    }
                }
            }
        }
    }

    if (!parsed) {
        /* Legacy fallback: [TYPE] details... with optional cmd= */
        p = raw;
        if (*p == '[') {
            p++;
            end = strchr(p, ']');
            if (end) {
                int len = (int)(end - p);
                if (len >= (int)sizeof(e->type))
                    len = (int)sizeof(e->type) - 1;
                strncpy(e->type, p, len);
                p = end + 1;
                while (*p == ' ')
                    p++;
            }
        } else {
            strncpy(e->type, "INFO", sizeof(e->type) - 1);
        }

        strncpy(e->msg, p, LINE_LEN - 1);

        strncpy(tmp, e->msg, LINE_LEN - 1);
        tok = strstr(tmp, "cmd=");
        if (tok) {
            tok += 4;
            {
                char *sp = strchr(tok, ' ');
                if (sp)
                    *sp = '\0';
            }
            strncpy(e->cmd, tok, W_CMD);
        } else {
            strncpy(e->cmd, "kernel", W_CMD);
        }
    }

    if (strcmp(e->type, "ALERT") == 0 && strstr(e->msg, "PTRACE"))
        e->cpair = CP_PTRACE;
    else if (strcmp(e->type, "ALERT") == 0)
        e->cpair = CP_ALERT;
    else if (strcmp(e->type, "RULE") == 0)
        e->cpair = CP_RULE;
    else if (strcmp(e->type, "OPEN") == 0)
        e->cpair = CP_OPEN;
    else
        e->cpair = CP_BASE;
}

/* ------------------------------------------------------------------ */
static void rebuild_filter(void)
{
    filtered_count = 0;
    for (int i = 0; i < total; i++) {
        const Entry *e = &entries[i];
        int pass = 0;
        switch (filter_mode) {
        case F_ALL:    pass = 1; break;
        case F_ALERT:  pass = strcmp(e->type, "ALERT") == 0
                               && !strstr(e->msg, "PTRACE"); break;
        case F_RULE:   pass = strcmp(e->type, "RULE")  == 0; break;
        case F_OPEN:   pass = strstr(e->msg, "file=") != NULL || (strcmp(e->type, "ALERT") == 0 && strstr(e->msg, "SENSITIVE_FILE") != NULL); break;
        case F_EXEC:   pass = strstr(e->msg,  "EXEC")  != NULL; break;
        case F_PTRACE: pass = strstr(e->msg,  "PTRACE")!= NULL; break;
        }
        if (pass)
            filtered[filtered_count++] = i;
    }
}

/* ------------------------------------------------------------------ */
static void read_proc(void)
{
    FILE *fp;
    char  buf[LINE_LEN];
    static char raw[MAX_LINES][LINE_LEN];
    int   i = 0;
    int   new_total = 0;

    fp = fopen("/proc/ids_monitor", "r");
    if (!fp) {
        if (total == 0) {
            strncpy(entries[0].time, "--:--:--",
                    sizeof(entries[0].time) - 1);
            strncpy(entries[0].cmd,  "monitor",
                    sizeof(entries[0].cmd)  - 1);
            strncpy(entries[0].type, "ERR",
                    sizeof(entries[0].type) - 1);
            strncpy(entries[0].msg,
                    "cannot open /proc/ids_monitor -- is the IDS module loaded?",
                    LINE_LEN - 1);
            entries[0].cpair = CP_ALERT;
            total = 1;
        }
        rebuild_filter();
        return;
    }

    /* read all raw lines first without touching entries[] */
    while (i < MAX_LINES && fgets(buf, LINE_LEN, fp)) {
        buf[strcspn(buf, "\n")] = '\0';
        if (buf[0] == '\0') continue;
        strncpy(raw[i], buf, LINE_LEN - 1);
        i++;
    }
    fclose(fp);
    new_total = i;

    /*
     * detect ring buffer wrap — if the kernel overwrote old slots
     * the line count can stay the same or shrink. reset everything.
     */
    if (new_total < total) {
        cnt_alert = cnt_rule = cnt_open = 0;
        memset(entries, 0, sizeof(entries));
        total = 0;
        for (int j = 0; j < new_total; j++) {
            parse_line(raw[j], &entries[j]);
            if (strcmp(entries[j].type, "ALERT") == 0){
            cnt_alert++;
            if (strstr(entries[j].msg, "SENSITIVE_FILE") != NULL) cnt_open++;
        }
        else if (strcmp(entries[j].type, "RULE") == 0)
            cnt_rule++;
        else if (strstr(entries[j].msg, "file=") != NULL) cnt_open++;
        }
        total = new_total;
        rebuild_filter();
        int vis = LINES - 8;
        if (vis < 1) vis = 1;
        if (scroll_top + vis < filtered_count)
            scroll_top = filtered_count - vis;
        if (scroll_top < 0) scroll_top = 0;
        return;
    }

    /* only parse entries that are NEW (index >= old total) */
    for (int j = total; j < new_total; j++) {
        parse_line(raw[j], &entries[j]);
        if (strcmp(entries[j].type, "ALERT") == 0){
            cnt_alert++;
            if (strstr(entries[j].msg, "SENSITIVE_FILE") != NULL) cnt_open++;
        }
        else if (strcmp(entries[j].type, "RULE") == 0)
            cnt_rule++;
        else if (strstr(entries[j].msg, "file=") != NULL) cnt_open++;
    }

    total = new_total;

    rebuild_filter();

    int vis = LINES - 8;
    if (vis < 1) vis = 1;
    if (scroll_top + vis < filtered_count)
        scroll_top = filtered_count - vis;
    if (scroll_top < 0) scroll_top = 0;
}

/* ------------------------------------------------------------------ */
static void draw_badge(int row, int col, const char *label, int cpair)
{
    attron(COLOR_PAIR(cpair) | A_BOLD);
    mvprintw(row, col, "[%-5s]", label);
    attroff(COLOR_PAIR(cpair) | A_BOLD);
}

/* ------------------------------------------------------------------ */
static void draw(void)
{
    int  cols = COLS;
    int  rows = LINES;
    int  vis  = rows - 8;
    char tbuf[12];
    time_t     now = time(NULL);
    struct tm *tm  = localtime(&now);

    if (vis < 1) vis = 1;
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm);

    erase();

    /* ── row 0: title bar ── */
    attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvhline(0, 0, ' ', cols);
    mvprintw(0, 2, "IDS MONITOR");
    mvprintw(0, cols - 20, "LIVE  %s", tbuf);
    attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);

    /* ── row 1: stat counters ── */
    attron(COLOR_PAIR(CP_DIM));
    mvhline(1, 0, ' ', cols);
    attroff(COLOR_PAIR(CP_DIM));

    attron(COLOR_PAIR(CP_STAT_T) | A_BOLD);
    mvprintw(1, 2, "%d", total);
    attroff(COLOR_PAIR(CP_STAT_T) | A_BOLD);
    attron(COLOR_PAIR(CP_DIM));
    mvprintw(1, 2 + (int)snprintf(NULL, 0, "%d", total), " total");
    attroff(COLOR_PAIR(CP_DIM));

    attron(COLOR_PAIR(CP_STAT_A) | A_BOLD);
    mvprintw(1, 18, "%d", cnt_alert);
    attroff(COLOR_PAIR(CP_STAT_A) | A_BOLD);
    attron(COLOR_PAIR(CP_DIM));
    mvprintw(1, 18 + (int)snprintf(NULL, 0, "%d", cnt_alert), " alerts");
    attroff(COLOR_PAIR(CP_DIM));

    attron(COLOR_PAIR(CP_STAT_R) | A_BOLD);
    mvprintw(1, 34, "%d", cnt_rule);
    attroff(COLOR_PAIR(CP_STAT_R) | A_BOLD);
    attron(COLOR_PAIR(CP_DIM));
    mvprintw(1, 34 + (int)snprintf(NULL, 0, "%d", cnt_rule), " rules");
    attroff(COLOR_PAIR(CP_DIM));

    attron(COLOR_PAIR(CP_STAT_O) | A_BOLD);
    mvprintw(1, 50, "%d", cnt_open);
    attroff(COLOR_PAIR(CP_STAT_O) | A_BOLD);
    attron(COLOR_PAIR(CP_DIM));
    mvprintw(1, 50 + (int)snprintf(NULL, 0, "%d", cnt_open), " file");
    attroff(COLOR_PAIR(CP_DIM));

    /* ── row 2: filter bar ── */
    attron(COLOR_PAIR(CP_DIM));
    mvhline(2, 0, ' ', cols);
    mvprintw(2, 2, "filter: ");
    attroff(COLOR_PAIR(CP_DIM));
    {
        int fx = 10;
        for (int f = 0; f < F_COUNT; f++) {
            if (f == filter_mode) {
                int fc = CP_BASE;
                if (f == F_ALERT || f == F_PTRACE) fc = CP_ALERT;
                else if (f == F_RULE)  fc = CP_RULE;
                else if (f == F_OPEN)  fc = CP_OPEN;
                else if (f == F_EXEC)  fc = CP_CMD;
                attron(COLOR_PAIR(fc) | A_BOLD | A_REVERSE);
            } else {
                attron(COLOR_PAIR(CP_DIM));
            }
            mvprintw(2, fx, " %s ", filter_names[f]);
            if (f == filter_mode)
                attroff(COLOR_PAIR(CP_BASE) | A_BOLD | A_REVERSE);
            else
                attroff(COLOR_PAIR(CP_DIM));
            fx += (int)strlen(filter_names[f]) + 3;
        }
    }

    /* ── row 3: separator ── */
    attron(COLOR_PAIR(CP_DIM));
    mvhline(3, 0, ACS_HLINE, cols);
    attroff(COLOR_PAIR(CP_DIM));

    /* ── row 4: column headers ── */
    attron(COLOR_PAIR(CP_DIM) | A_BOLD);
    mvhline(4, 0, ' ', cols);
    mvprintw(4, 2, "%-*s", W_TIME, "TIME");
    mvprintw(4, 2 + W_TIME + 2,           "%-*s", W_CMD,      "COMMAND");
    mvprintw(4, 2 + W_TIME + 2 + W_CMD + 2, "%-*s", W_TYPE + 2, "TYPE");
    mvprintw(4, 2 + W_TIME + 2 + W_CMD + 2 + W_TYPE + 4, "DETAILS");
    attroff(COLOR_PAIR(CP_DIM) | A_BOLD);

    /* ── row 5: separator ── */
    attron(COLOR_PAIR(CP_DIM));
    mvhline(5, 0, ACS_HLINE, cols);
    attroff(COLOR_PAIR(CP_DIM));

    /* ── rows 6..rows-2: log entries ── */
    int row   = 6;
    int shown = 0;
    int msg_x = 2 + W_TIME + 2 + W_CMD + 2 + W_TYPE + 4;
    int msg_w = cols - msg_x - 1;
    if (msg_w < 8) msg_w = 8;

    for (int fi = scroll_top; fi < filtered_count && shown < vis; fi++) {
        const Entry *e = &entries[filtered[fi]];

        move(row, 0);
        clrtoeol();

        attron(COLOR_PAIR(e->cpair) | A_BOLD);
        mvaddch(row, 0, ACS_VLINE);
        attroff(COLOR_PAIR(e->cpair) | A_BOLD);

        attron(COLOR_PAIR(CP_DIM));
        mvprintw(row, 2, "%-*s", W_TIME, e->time);
        attroff(COLOR_PAIR(CP_DIM));

        attron(COLOR_PAIR(CP_CMD) | A_BOLD);
        mvprintw(row, 2 + W_TIME + 2, "%-*s", W_CMD, e->cmd);
        attroff(COLOR_PAIR(CP_CMD) | A_BOLD);

        draw_badge(row, 2 + W_TIME + 2 + W_CMD + 2, e->type, e->cpair);

        attron(COLOR_PAIR(CP_BASE));
        mvprintw(row, msg_x, "%.*s", msg_w, e->msg);
        attroff(COLOR_PAIR(CP_BASE));

        row++;
        shown++;
    }

    /* clear any leftover rows below last entry */
    while (row < rows - 1) {
        move(row, 0);
        clrtoeol();
        row++;
    }

    /* ── footer ── */
    attron(COLOR_PAIR(CP_HEADER));
    mvhline(rows - 1, 0, ' ', cols);
    mvprintw(rows - 1, 2,
             "^/v scroll  PgUp/PgDn page  [F] filter  [Q] quit"
             "   %d-%d of %d (total: %d)",
             filtered_count ? scroll_top + 1       : 0,
             filtered_count ? scroll_top + shown   : 0,
             filtered_count,
             total);
    attroff(COLOR_PAIR(CP_HEADER));

    wnoutrefresh(stdscr);
    doupdate();
}

/* ------------------------------------------------------------------ */
int main(void)
{
    initscr();
    noecho();
    curs_set(FALSE);
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    cbreak();
    signal(SIGWINCH, handle_resize);

    if (!has_colors()) {
        endwin();
        fprintf(stderr, "terminal does not support colors\n");
        return 1;
    }

    start_color();
    use_default_colors();
    init_pair(CP_BASE,   COLOR_WHITE,   -1);
    init_pair(CP_ALERT,  COLOR_RED,     -1);
    init_pair(CP_RULE,   COLOR_YELLOW,  -1);
    init_pair(CP_OPEN,   COLOR_GREEN,   -1);
    init_pair(CP_PTRACE, COLOR_MAGENTA, -1);
    init_pair(CP_CMD,    COLOR_CYAN,    -1);
    init_pair(CP_DIM,    8,             -1);
    init_pair(CP_HEADER, COLOR_BLACK,   COLOR_BLUE);
    init_pair(CP_STAT_A, COLOR_RED,     -1);
    init_pair(CP_STAT_R, COLOR_YELLOW,  -1);
    init_pair(CP_STAT_O, COLOR_GREEN,   -1);
    init_pair(CP_STAT_T, COLOR_CYAN,    -1);
    init_pair(CP_FILTER, COLOR_BLACK,   COLOR_WHITE);

    read_proc();

    int tick  = 0;
    int dirty = 1;

    while (1) {
        int ch = getch();

        switch (ch) {
        case 'q': case 'Q':
            endwin();
            return 0;

        case KEY_RESIZE:
            need_resize = 1;
            break;

        case 'f': case 'F':
            filter_mode = (filter_mode + 1) % F_COUNT;
            scroll_top  = 0;
            rebuild_filter();
            dirty = 1;
            break;

        case KEY_UP:
            if (scroll_top > 0) { scroll_top--; dirty = 1; }
            break;

        case KEY_DOWN: {
            int vis = LINES - 8;
            if (vis < 1) vis = 1;
            if (scroll_top + vis < filtered_count)
                { scroll_top++; dirty = 1; }
            break;
        }

        case KEY_PPAGE:
            scroll_top -= (LINES - 8);
            if (scroll_top < 0) scroll_top = 0;
            dirty = 1;
            break;

        case KEY_NPAGE: {
            int vis = LINES - 8;
            if (vis < 1) vis = 1;
            scroll_top += vis;
            if (scroll_top + vis > filtered_count)
                scroll_top = filtered_count - vis;
            if (scroll_top < 0) scroll_top = 0;
            dirty = 1;
            break;
        }
        }

        if (need_resize) {
            endwin();
            refresh();
            clear();
            need_resize = 0;
            dirty = 1;
        }

        tick++;
        if (tick >= 10) {
            int old = total;
            read_proc();
            tick = 0;
            if (total != old) dirty = 1;
        }

        if (dirty) {
            draw();
            dirty = 0;
        }

        usleep(50000);
    }

    endwin();
    return 0;
}
