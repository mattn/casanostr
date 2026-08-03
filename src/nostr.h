#ifndef CASANOSTR_NOSTR_H
#define CASANOSTR_NOSTR_H

#include <stdbool.h>
#include <stddef.h>
#include "cJSON.h"

/* Validate a nostr event: structure, id and BIP-340 schnorr signature.
 * Returns NULL when valid, otherwise a static error message suitable
 * for the machine-readable part of an OK message. */
const char *nostr_event_validate(const cJSON *ev);

/* NIP-01 canonical serialization [0,pubkey,created_at,kind,tags,content].
 * Caller must free. Returns NULL on malformed event. */
char *nostr_event_canonical(const cJSON *ev);

/* Compute the event id into id_hex (65 bytes, lowercase hex + NUL). */
bool nostr_event_id(const cJSON *ev, char *id_hex);

/* Does the event match a single filter object / any filter in an array? */
bool nostr_filter_match(const cJSON *filter, const cJSON *ev);
bool nostr_filters_match(const cJSON *filters, const cJSON *ev);

/* Is s exactly len characters of lowercase hex? */
bool nostr_is_hex(const char *s, size_t len);

#endif
