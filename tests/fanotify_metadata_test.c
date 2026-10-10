#include "../src/fanotify_records.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(void) {
    struct fanotify_event_metadata meta;
    memset(&meta, 0, sizeof(meta));
    meta.vers = FANOTIFY_METADATA_VERSION;
    meta.event_len = (uint8_t)sizeof(meta);
    meta.metadata_len = (uint16_t)sizeof(meta);
    meta.fd = FAN_NOFD;

    CHECK(metadata_record_valid(&meta, sizeof(meta)));
    CHECK(!metadata_record_valid(&meta, sizeof(meta) - 1U));

    meta.vers = (uint8_t)(FANOTIFY_METADATA_VERSION + 1U);
    CHECK(!metadata_record_valid(&meta, sizeof(meta)));
    meta.vers = FANOTIFY_METADATA_VERSION;

    meta.event_len = (uint8_t)(sizeof(meta) - 1U);
    CHECK(!metadata_record_valid(&meta, sizeof(meta)));
    meta.event_len = (uint8_t)sizeof(meta);

    meta.event_len = (uint8_t)(sizeof(meta) + 1U);
    CHECK(!metadata_record_valid(&meta, sizeof(meta)));
    CHECK(!metadata_record_valid(&meta, sizeof(meta) + 8U));
    meta.event_len = (uint8_t)sizeof(meta);

    meta.metadata_len = (uint16_t)(sizeof(meta) - 1U);
    CHECK(!metadata_record_valid(&meta, sizeof(meta)));
    meta.metadata_len = (uint16_t)(sizeof(meta) + 1U);
    CHECK(!metadata_record_valid(&meta, sizeof(meta)));
    meta.metadata_len = (uint16_t)sizeof(meta);

    meta.reserved = 1U;
    CHECK(!metadata_record_valid(&meta, sizeof(meta)));

    CHECK(strcmp(event_operation(FAN_OPEN), "open_observed") == 0);
    CHECK(strcmp(event_operation(FAN_CLOSE_WRITE), "close_write_observed") == 0);
    CHECK(strcmp(event_operation(FAN_Q_OVERFLOW), "queue_overflow") == 0);
    CHECK(strcmp(event_operation(FAN_ACCESS), "unknown_event") == 0);
    return 0;
}
