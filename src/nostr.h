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

/* The wire form of a stored event: the seven NIP-01 fields in a fixed
 * order. Both build from the fields the store holds, so a row rebuilt from
 * its columns and a freshly accepted event serialize identically.
 * Caller must free; NULL on a malformed event. */
char *nostr_event_serialize(const char *id, const char *pubkey,
                            long long created_at, int kind,
                            const char *tags_json, const char *content,
                            const char *sig);
char *nostr_event_json(const cJSON *ev);

/* Does the event match a single filter object / any filter in an array? */
bool nostr_filter_match(const cJSON *filter, const cJSON *ev);
bool nostr_filters_match(const cJSON *filters, const cJSON *ev);

/* Is s exactly len characters of lowercase hex? */
bool nostr_is_hex(const char *s, size_t len);

/* First value of the first tag named `name`, or NULL if absent.
 * A tag without a value yields "". */
const char *nostr_tag_value(const cJSON *ev, const char *name);

#endif
