#ifndef DIRGUARD_FANOTIFY_RECORDS_H
#define DIRGUARD_FANOTIFY_RECORDS_H

#include <errno.h>
#include <linux/fanotify.h>
#include <stddef.h>
#include <stdint.h>

static inline int metadata_record_valid(const struct fanotify_event_metadata *meta,
                                        size_t remaining) {
    if (remaining < sizeof(*meta) || meta->vers != FANOTIFY_METADATA_VERSION ||
        meta->reserved != 0U || meta->event_len < sizeof(*meta) ||
        (size_t)meta->event_len > remaining ||
        meta->event_len % _Alignof(struct fanotify_event_metadata) != 0U ||
        meta->metadata_len < sizeof(*meta) || meta->metadata_len > meta->event_len) {
        errno = EPROTO;
        return 0;
    }
    return 1;
}

static inline const char *event_operation(uint64_t mask) {
    if (mask & FAN_Q_OVERFLOW) return "queue_overflow";
    if (mask & FAN_CLOSE_WRITE) return "close_write_observed";
    if (mask & FAN_OPEN) return "open_observed";
    return "unknown_event";
}

#endif
