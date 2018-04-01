/*
 * contact-hashes, Calculating a hash from phone number or email addresses
 *
 * ISC License
 *
 * Copyright (C) 2017 1984not Security GmbH
 * Author: Max Bruckner (FSMaxB)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "contact-hashes.h"

char *hash_contact(const char * const contact, const size_t contact_length) {
	const int algorithm = 2; // crypto_pwhash_argon2id_ALG_ARGON2ID13
	const size_t opslimit = 2U;
	const size_t memlimit = 4U * 1024U * 1024U; // 1 MiB
	const size_t hash_bytes = 32U;
	const unsigned char salt[] = "1984not contact";

	assert(sizeof(salt) == crypto_pwhash_argon2i_SALTBYTES);

	if (sodium_init() < 0) {
		return NULL;
	}

	unsigned char hash[hash_bytes];

	/* calculate the hash */
	int status = crypto_pwhash(
			hash,
			sizeof(hash),
			contact,
			contact_length,
			salt,
			opslimit,
			memlimit,
			algorithm);
	if (status != 0) {
		return NULL;
	}

	/* encode as HEX */
	char hex_hash[2 * hash_bytes + 1];
	if (sodium_bin2hex(hex_hash, sizeof(hex_hash), hash, sizeof(hash)) == NULL) {
		return NULL;
	}

	/* encode it into a general format */
	const size_t max_encoded_size = sizeof("argon2id13-18446744073709551615-18446744073709551615-000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
	char *encoded_hash = malloc(max_encoded_size);
	if (encoded_hash == NULL) {
		return NULL;
	}
	snprintf(encoded_hash, max_encoded_size, "argon2id13-%zu-%zu-%s", opslimit, memlimit, hex_hash);

	return encoded_hash;
}
