#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <uci.h>

/* ── helpers ─────────────────────────────────────────────────── */

static const char *uci_get(struct uci_context *ctx,
                            struct uci_section *s, const char *opt)
{
    struct uci_option *o = uci_lookup_option(ctx, s, opt);
    if (o && o->type == UCI_TYPE_STRING)
        return o->v.string;
    return NULL;
}

static int64_t parse_fixed(const char *s, int64_t scale)
{
    if (!s || !*s) return 0;

    int neg = 0;
    if (*s == '-') { neg = 1; s++; }

    int64_t intpart  = 0;
    int64_t fracpart = 0;
    int64_t fracdiv  = 1;

    while (*s >= '0' && *s <= '9')
        intpart = intpart * 10 + (*s++ - '0');

    if (*s == '.') {
        s++;
        while (*s >= '0' && *s <= '9') {
            fracpart = fracpart * 10 + (*s++ - '0');
            fracdiv *= 10;
        }
    }

    int64_t result = intpart * scale + fracpart * scale / fracdiv;
    return neg ? -result : result;
}

#define UCI_STR(field, name) \
    do { const char *_v = uci_get(ctx, sec, name); \
         if (_v) snprintf(cfg->field, sizeof(cfg->field), "%s", _v); } while(0)

#define UCI_INT(field, name) \
    do { const char *_v = uci_get(ctx, sec, name); \
         if (_v) cfg->field = (int)strtol(_v, NULL, 10); } while(0)

#define UCI_U32(field, name) \
    do { const char *_v = uci_get(ctx, sec, name); \
         if (_v) cfg->field = (uint32_t)strtoul(_v, NULL, 10); } while(0)

#define UCI_MS_US(field, name) \
    do { const char *_v = uci_get(ctx, sec, name); \
         if (_v) cfg->field = parse_fixed(_v, 1000LL); } while(0)

#define UCI_S_US(field, name) \
    do { const char *_v = uci_get(ctx, sec, name); \
         if (_v) cfg->field = parse_fixed(_v, 1000000LL); } while(0)

#define UCI_FP(field, name) \
    do { const char *_v = uci_get(ctx, sec, name); \
         if (_v) cfg->field = parse_fixed(_v, 1000000LL); } while(0)

/* ── defaults ────────────────────────────────────────────────── */

void config_set_defaults(cake_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    snprintf(cfg->dl_if, sizeof(cfg->dl_if), "ifb-wan");
    snprintf(cfg->ul_if, sizeof(cfg->ul_if), "wan");

    cfg->enabled                 = 0;
    cfg->adjust_dl_shaper_rate   = 1;
    cfg->adjust_ul_shaper_rate   = 1;
    cfg->min_dl_shaper_rate_kbps  = 5000;
    cfg->base_dl_shaper_rate_kbps = 20000;
    cfg->max_dl_shaper_rate_kbps  = 80000;
    cfg->min_ul_shaper_rate_kbps  = 5000;
    cfg->base_ul_shaper_rate_kbps = 20000;
    cfg->max_ul_shaper_rate_kbps  = 35000;
    cfg->connection_active_thr_kbps = 2000;

    cfg->no_pingers                 = 6;
    cfg->reflector_ping_interval_us = 300000;

    static const char *def_refs[] = {
        "1.1.1.1", "1.0.0.1",
        "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "9.9.9.10",
        "94.140.14.15",  "94.140.14.140",
        "208.67.220.220","208.67.222.222",
        NULL
    };
    cfg->no_reflectors = 0;
    for (int i = 0; def_refs[i] && i < MAX_REFLECTORS; i++) {
        snprintf(cfg->reflectors[i], 64, "%s", def_refs[i]);
        cfg->no_reflectors++;
    }

    cfg->dl_avg_owd_delta_max_adjust_up_thr_us   = 10000;
    cfg->ul_avg_owd_delta_max_adjust_up_thr_us   = 10000;
    cfg->dl_owd_delta_delay_thr_us               = 30000;
    cfg->ul_owd_delta_delay_thr_us               = 30000;
    cfg->dl_avg_owd_delta_max_adjust_down_thr_us = 60000;
    cfg->ul_avg_owd_delta_max_adjust_down_thr_us = 60000;

    cfg->alpha_baseline_increase =    1000;
    cfg->alpha_baseline_decrease = 900000;
    cfg->alpha_delta_ewma        =  95000;

    cfg->shaper_rate_min_adjust_down_bufferbloat = 990000;
    cfg->shaper_rate_max_adjust_down_bufferbloat = 750000;
    cfg->shaper_rate_min_adjust_up_load_high     = 1000000;
    cfg->shaper_rate_max_adjust_up_load_high     = 1040000;
    cfg->shaper_rate_adjust_down_load_low        = 990000;
    cfg->shaper_rate_adjust_up_load_low          = 1010000;

    cfg->bufferbloat_detection_window = 6;
    cfg->bufferbloat_detection_thr    = 3;
    cfg->high_load_thr                = 750000;

    cfg->bufferbloat_refractory_period_us = 300000;
    cfg->decay_refractory_period_us       = 1000000;

    cfg->reflector_health_check_interval_us     = 1000000;
    cfg->reflector_response_deadline_us         = 1000000;
    cfg->reflector_misbehaving_detection_window = 60;
    cfg->reflector_misbehaving_detection_thr    = 3;
    cfg->reflector_replacement_interval_us      = 3600LL * 1000000LL;
    cfg->reflector_comparison_interval_us       =   60LL * 1000000LL;
    cfg->reflector_sum_owd_baselines_delta_thr_us = 20000;
    cfg->reflector_owd_delta_ewma_delta_thr_us    = 10000;

    cfg->stall_detection_thr             = 5;
    cfg->connection_stall_thr_kbps       = 10;
    cfg->global_ping_response_timeout_us = 10000000;

    cfg->sustained_idle_sleep_thr_us         = 60000000;
    cfg->min_shaper_rates_enforcement        = 0;
    cfg->enable_sleep_function               = 1;
    cfg->startup_wait_us                     = 0;
    cfg->monitor_achieved_rates_interval_us  = 200000;
    cfg->if_up_check_interval_us             = 10000000;

    cfg->cake_overhead   = 0;
    cfg->cake_mpu        = 0;
    cfg->cake_nat        = 1;
    cfg->cake_wash       = 1;
    cfg->cake_ack_filter = 0;
    cfg->cake_diffserv   = 1;
    cfg->cake_flow_mode  = 7;
    cfg->cake_dl_flow_mode = -1;
    cfg->cake_ul_flow_mode = -1;
    cfg->cake_atm        = 0;
    cfg->cake_rtt_us     = 0;
    cfg->cake_split_gso  = 1;
    cfg->cake_mq         = 0;

    cfg->smart_shaping_enabled          = 0;
    cfg->smart_shaping_enable_delay_us  = 3000000;
    cfg->smart_shaping_disable_delay_us = 10000000;
    snprintf(cfg->gaming_rules_file, sizeof(cfg->gaming_rules_file),
             "/etc/darkmoon/gaming-ports.txt");
    cfg->smart_shaping_offload_enabled  = 0;
    snprintf(cfg->lan_if, sizeof(cfg->lan_if), "br-lan");

    cfg->ping_type = 0;
    cfg->reflectors_file[0] = '\0';
}

/* ── UCI load ────────────────────────────────────────────────── */

int config_load(const char *section_name, cake_config_t *cfg)
{
    struct uci_context *ctx;
    struct uci_package *pkg;
    struct uci_section *sec;

    config_set_defaults(cfg);

    ctx = uci_alloc_context();
    if (!ctx) return -1;

    if (uci_load(ctx, "darkmoon", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        return -1;
    }

    sec = uci_lookup_section(ctx, pkg, section_name);
    if (!sec) {
        uci_unload(ctx, pkg);
        uci_free_context(ctx);
        return -1;
    }

    snprintf(cfg->instance_id, sizeof(cfg->instance_id), "%s", section_name);

    UCI_INT(enabled,                    "enabled");
    UCI_STR(dl_if,                      "dl_if");
    UCI_STR(ul_if,                      "ul_if");
    UCI_INT(adjust_dl_shaper_rate,      "adjust_dl_shaper_rate");
    UCI_INT(adjust_ul_shaper_rate,      "adjust_ul_shaper_rate");
    UCI_U32(min_dl_shaper_rate_kbps,    "min_dl_shaper_rate_kbps");
    UCI_U32(base_dl_shaper_rate_kbps,   "base_dl_shaper_rate_kbps");
    UCI_U32(max_dl_shaper_rate_kbps,    "max_dl_shaper_rate_kbps");
    UCI_U32(min_ul_shaper_rate_kbps,    "min_ul_shaper_rate_kbps");
    UCI_U32(base_ul_shaper_rate_kbps,   "base_ul_shaper_rate_kbps");
    UCI_U32(max_ul_shaper_rate_kbps,    "max_ul_shaper_rate_kbps");
    UCI_U32(connection_active_thr_kbps, "connection_active_thr_kbps");

    UCI_INT(no_pingers,                  "no_pingers");
    UCI_S_US(reflector_ping_interval_us, "reflector_ping_interval_s");

    struct uci_option *refl_opt = uci_lookup_option(ctx, sec, "reflectors");
    if (refl_opt && refl_opt->type == UCI_TYPE_LIST) {
        int idx = 0;
        struct uci_element *e;
        uci_foreach_element(&refl_opt->v.list, e) {
            if (idx >= MAX_REFLECTORS) break;
            snprintf(cfg->reflectors[idx++], 64, "%s", e->name);
        }
        cfg->no_reflectors = idx;
    }

    UCI_MS_US(dl_avg_owd_delta_max_adjust_up_thr_us,   "dl_avg_owd_delta_max_adjust_up_thr_ms");
    UCI_MS_US(ul_avg_owd_delta_max_adjust_up_thr_us,   "ul_avg_owd_delta_max_adjust_up_thr_ms");
    UCI_MS_US(dl_owd_delta_delay_thr_us,               "dl_owd_delta_delay_thr_ms");
    UCI_MS_US(ul_owd_delta_delay_thr_us,               "ul_owd_delta_delay_thr_ms");
    UCI_MS_US(dl_avg_owd_delta_max_adjust_down_thr_us, "dl_avg_owd_delta_max_adjust_down_thr_ms");
    UCI_MS_US(ul_avg_owd_delta_max_adjust_down_thr_us, "ul_avg_owd_delta_max_adjust_down_thr_ms");

    UCI_FP(alpha_baseline_increase, "alpha_baseline_increase");
    UCI_FP(alpha_baseline_decrease, "alpha_baseline_decrease");
    UCI_FP(alpha_delta_ewma,        "alpha_delta_ewma");

    UCI_FP(shaper_rate_min_adjust_down_bufferbloat, "shaper_rate_min_adjust_down_bufferbloat");
    UCI_FP(shaper_rate_max_adjust_down_bufferbloat, "shaper_rate_max_adjust_down_bufferbloat");
    UCI_FP(shaper_rate_min_adjust_up_load_high,     "shaper_rate_min_adjust_up_load_high");
    UCI_FP(shaper_rate_max_adjust_up_load_high,     "shaper_rate_max_adjust_up_load_high");
    UCI_FP(shaper_rate_adjust_down_load_low,        "shaper_rate_adjust_down_load_low");
    UCI_FP(shaper_rate_adjust_up_load_low,          "shaper_rate_adjust_up_load_low");

    UCI_INT(bufferbloat_detection_window, "bufferbloat_detection_window");
    UCI_INT(bufferbloat_detection_thr,    "bufferbloat_detection_thr");
    UCI_FP (high_load_thr,                "high_load_thr");
    
    /* Clamp critical window sizes to prevent divide-by-zero crashes */
    if (cfg->bufferbloat_detection_window < 1) cfg->bufferbloat_detection_window = 1;
    if (cfg->bufferbloat_detection_thr < 1) cfg->bufferbloat_detection_thr = 1;

    UCI_MS_US(bufferbloat_refractory_period_us, "bufferbloat_refractory_period_ms");
    UCI_MS_US(decay_refractory_period_us,       "decay_refractory_period_ms");

    UCI_S_US(reflector_health_check_interval_us,     "reflector_health_check_interval_s");
    UCI_S_US(reflector_response_deadline_us,         "reflector_response_deadline_s");
    UCI_INT (reflector_misbehaving_detection_window, "reflector_misbehaving_detection_window");
    UCI_INT (reflector_misbehaving_detection_thr,    "reflector_misbehaving_detection_thr");
    UCI_S_US(reflector_replacement_interval_us,      "reflector_replacement_interval_s");
    UCI_S_US(reflector_comparison_interval_us,       "reflector_comparison_interval_s");
    UCI_MS_US(reflector_sum_owd_baselines_delta_thr_us, "reflector_sum_owd_baselines_delta_thr_ms");
    UCI_MS_US(reflector_owd_delta_ewma_delta_thr_us,    "reflector_owd_delta_ewma_delta_thr_ms");

    if (cfg->reflector_misbehaving_detection_window < 1) cfg->reflector_misbehaving_detection_window = 1;

    UCI_INT  (stall_detection_thr,             "stall_detection_thr");
    UCI_U32  (connection_stall_thr_kbps,       "connection_stall_thr_kbps");
    UCI_S_US (global_ping_response_timeout_us, "global_ping_response_timeout_s");

    UCI_S_US (sustained_idle_sleep_thr_us,         "sustained_idle_sleep_thr_s");
    UCI_INT  (min_shaper_rates_enforcement,         "min_shaper_rates_enforcement");
    UCI_INT  (enable_sleep_function,                "enable_sleep_function");
    UCI_S_US (startup_wait_us,                      "startup_wait_s");
    UCI_MS_US(monitor_achieved_rates_interval_us,   "monitor_achieved_rates_interval_ms");
    UCI_S_US (if_up_check_interval_us,              "if_up_check_interval_s");

    {
        const char *_v = uci_get(ctx, sec, "cake_overhead");
        if (_v)
            cfg->cake_overhead = (int32_t)strtol(_v, NULL, 10);
    }

    UCI_U32(cake_mpu,        "cake_mpu");
    UCI_INT(cake_nat,        "cake_nat");
    UCI_INT(cake_wash,       "cake_wash");
    UCI_INT(cake_ack_filter, "cake_ack_filter");
    UCI_INT(cake_diffserv,   "cake_diffserv");
    UCI_INT(cake_flow_mode,  "cake_flow_mode");

    {
        const char *_v = uci_get(ctx, sec, "cake_dl_flow_mode");
        if (_v) cfg->cake_dl_flow_mode = (int)strtol(_v, NULL, 10);
    }
    {
        const char *_v = uci_get(ctx, sec, "cake_ul_flow_mode");
        if (_v) cfg->cake_ul_flow_mode = (int)strtol(_v, NULL, 10);
    }

    if (cfg->cake_dl_flow_mode < 0)
        cfg->cake_dl_flow_mode = cfg->cake_flow_mode;
    if (cfg->cake_ul_flow_mode < 0)
        cfg->cake_ul_flow_mode = cfg->cake_flow_mode;

    UCI_INT(cake_atm,        "cake_atm");
    UCI_INT(cake_split_gso,  "cake_split_gso");
    UCI_INT(cake_mq,         "cake_mq");

    {
        const char *_v = uci_get(ctx, sec, "cake_rtt_ms");
        if (_v)
            cfg->cake_rtt_us = (uint32_t)(strtoul(_v, NULL, 10) * 1000UL);
    }

    UCI_INT(ping_type,       "ping_type");
    UCI_STR(reflectors_file, "reflectors_file");

    UCI_INT (smart_shaping_enabled,          "smart_shaping_enabled");
    UCI_S_US(smart_shaping_enable_delay_us,  "smart_shaping_enable_delay_s");
    UCI_S_US(smart_shaping_disable_delay_us, "smart_shaping_disable_delay_s");
    UCI_STR (gaming_rules_file,              "gaming_rules_file");
    UCI_INT (smart_shaping_offload_enabled,  "smart_shaping_offload_enabled");
    UCI_STR (lan_if,                         "lan_if");

    uci_unload(ctx, pkg);
    uci_free_context(ctx);

    if (cfg->reflectors_file[0] != '\0') {
        FILE *fp = fopen(cfg->reflectors_file, "r");
        if (fp) {
            char line[256];
            int  count = 0;
            while (fgets(line, sizeof(line), fp) && count < MAX_REFLECTORS) {
                int len = (int)strlen(line);
                while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||
                                   line[len-1] == ' '  || line[len-1] == '\t'))
                    line[--len] = '\0';
                if (len == 0 || line[0] == '#')
                    continue;

                int valid = 1;
                for (int ci = 0; ci < len; ci++) {
                    if (line[ci] != '.' &&
                        (line[ci] < '0' || line[ci] > '9')) {
                        valid = 0;
                        break;
                    }
                }
                if (!valid)
                    continue;

                snprintf(cfg->reflectors[count++], 64, "%s", line);
            }
            fclose(fp);

            if (count > 1) {
                unsigned int seed;
                int urfd = open("/dev/urandom", O_RDONLY);
                if (urfd >= 0) {
                    if (read(urfd, &seed, sizeof(seed)) != sizeof(seed))
                        seed = (unsigned int)time(NULL);
                    close(urfd);
                } else {
                    seed = (unsigned int)time(NULL);
                }
                srand(seed);
                for (int i = count - 1; i > 0; i--) {
                    int j = rand() % (i + 1);
                    char tmp[64];
                    memcpy(tmp,                cfg->reflectors[i], 64);
                    memcpy(cfg->reflectors[i], cfg->reflectors[j], 64);
                    memcpy(cfg->reflectors[j], tmp,                64);
                }
            }
            cfg->no_reflectors = count;
        }
    }

    return 0;
}
