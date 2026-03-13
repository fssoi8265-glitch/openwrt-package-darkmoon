/*
 * traffic_detector.h  –  nftables counter-based latency-sensitive traffic detector
 *
 * Part of the darkmoon-shaper feature.
 *
 * HOW IT WORKS
 * ────────────
 * Instead of sniffing packets with AF_PACKET (which is unreliable on DSA/VLAN
 * subinterfaces common in OpenWrt), this module reads an nftables named counter
 * that is embedded directly in the darkmoon_dscp forwarding chain.
 *
 * The counter rule sits at the end of the chain and counts any packet whose
 * DSCP has already been set to a non-default value by the earlier port-matching
 * rules:
 *
 *   ip dscp != cs0 counter name gaming_pkts
 *
 * Every TDETECT_COUNTER_POLL_US (1 second), traffic_detector_poll() runs:
 *
 *   nft list counter inet darkmoon_dscp gaming_pkts
 *
 * and checks whether the packet count has increased since the last poll.
 * If it has, "sensitive traffic seen" is true for this interval.
 *
 * WHY NOT AF_PACKET
 * ─────────────────
 * AF_PACKET + PACKET_RECV_OUTPUT does not reliably deliver TX frames on DSA
 * subinterfaces (wan@eth0, eth0.2, etc.) on OpenWrt kernels.  The nftables
 * counter lives in the same kernel path that is already doing the DSCP marking,
 * so it is guaranteed to see every marked packet.
 *
 * OVERHEAD
 * ────────
 * One fork/exec of nft per second.  nft on OpenWrt is ~200 KB; startup cost
 * is negligible on any router fast enough to run CAKE at useful speeds.
 *
 * HYSTERESIS STATE MACHINE
 * ────────────────────────
 *   IDLE ──[counter increments for enable_delay]──► ACTIVE
 *   ACTIVE ──[counter silent for disable_delay]──► IDLE
 *   (through ARMING / COOLING intermediate states to prevent flapping)
 */

#ifndef TRAFFIC_DETECTOR_H
#define TRAFFIC_DETECTOR_H

#include <stdint.h>

/* nftables table and counter names – must match dscp_rules_load() in main.c */
#define TDETECT_NFT_TABLE   "darkmoon_dscp"
#define TDETECT_NFT_COUNTER "gaming_pkts"

/*
 * How often to poll the nftables counter (µs).
 * 1 second is sufficient given hysteresis delays of 3–10 s.
 */
#define TDETECT_COUNTER_POLL_US  1000000LL   /* 1 s */

/*
 * TDETECT_ARM_GRACE_US – how long the counter may be silent during ARMING
 * before we give up and reset to IDLE.
 *
 * Must be SHORTER than enable_delay_us (default 3 s) so that a single
 * stray packet can never accumulate enough silent time to reach the
 * enable_delay threshold.  2 s means: if traffic stops for 2 s while
 * still arming, it was not a real game session.
 */
#define TDETECT_ARM_GRACE_US     2000000LL   /* 2 s – must be < enable_delay */

/*
 * TDETECT_ACTIVE_GRACE_US – how long the counter may be silent while ACTIVE
 * before transitioning to COOLING.  Game traffic is bursty; loading screens,
 * respawn timers, and menu navigation can pause packets for several seconds.
 * 5 s prevents unnecessary COOLING transitions during normal game play.
 */
#define TDETECT_ACTIVE_GRACE_US  5000000LL   /* 5 s */

/* ── Internal state machine ──────────────────────────────────── */

typedef enum {
    TDETECT_IDLE    = 0,  /* No sensitive traffic; shaping is bypassed      */
    TDETECT_ARMING  = 1,  /* Counter incrementing; waiting for enable_delay */
    TDETECT_ACTIVE  = 2,  /* Traffic confirmed; shaping engaged             */
    TDETECT_COOLING = 3,  /* Counter silent; waiting for disable_delay      */
} tdetect_state_t;

/* ── Public struct ───────────────────────────────────────────── */

typedef struct {
    /* Whether init succeeded (0 = ok, -1 = nft not available) */
    int             ready;

    /* State machine */
    tdetect_state_t state;

    /* Timestamps (monotonic µs) for hysteresis and poll throttle */
    int64_t         t_arm_start_us;
    int64_t         t_cool_start_us;
    int64_t         t_last_poll_us;
    int64_t         t_last_traffic_us;  /* last time counter actually incremented */

    /* Hysteresis delays (µs) – set from config */
    int64_t         enable_delay_us;
    int64_t         disable_delay_us;

    /* nftables counter state */
    uint64_t        prev_pkt_count;
    int             counter_active;   /* did counter increment in last poll? */

    /* Diagnostic counters */
    uint64_t        activations;
} traffic_detector_t;

/* ── Public API ──────────────────────────────────────────────── */

/*
 * traffic_detector_init – initialise the detector.
 *
 * Verifies that `nft` is available and the darkmoon_dscp counter exists.
 * On failure sets ready = -1; detector conservatively reports always-active.
 */
int traffic_detector_init(traffic_detector_t *td,
                          int64_t             enable_delay_us,
                          int64_t             disable_delay_us);

/*
 * traffic_detector_cleanup – reset the struct (nothing to close).
 */
void traffic_detector_cleanup(traffic_detector_t *td);

/*
 * traffic_detector_poll – read the nftables counter and advance state machine.
 * Throttled to once per TDETECT_COUNTER_POLL_US regardless of call frequency.
 * Returns 1 if shaping should be active, 0 if bypassed.
 */
int traffic_detector_poll(traffic_detector_t *td, int64_t t_now_us);

/*
 * traffic_detector_is_active – 1 if CAKE shaping should be engaged.
 * Always 1 if init failed (conservative fallback).
 */
static inline int traffic_detector_is_active(const traffic_detector_t *td)
{
    if (td->ready != 0)
        return 1;
    return (td->state == TDETECT_ACTIVE || td->state == TDETECT_COOLING);
}

#endif /* TRAFFIC_DETECTOR_H */
