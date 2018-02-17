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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "contact-hashes.h"

static bool compare_hash(const char * const expected, const char * const contact) {
	char *hash = hash_contact(contact, strlen(contact));
	if (hash == NULL) {
		return false;
	}
	printf("contact: %s, hash: %s\n", contact, hash);

	int comparison = strcmp(expected, hash);
	free(hash);

	return (comparison == 0);
}

int main(void) {
	// test a scenario with 200 contacts with email address and phone number
	for (size_t i = 0; i < 400; i++) {
		char contact[] = "test-contact";
		char *hash = hash_contact(contact, sizeof(contact));
		if (hash == NULL) {
			return EXIT_FAILURE;
		}
		free(hash);
	}

	if (!compare_hash("argon2id13-2-4194304-127c38610ad65051c31f0be0e9241186dee7192f6e456ee9d5ef19a7393029a5", "fsmaxb@1984not.de")) {
		return EXIT_FAILURE;
	}
	if (!compare_hash("argon2id13-2-4194304-eebd52b2b1d34a47816741e6b722e5d02ae7ed0d843c6722d521025b7f1f8d5c", "+19995550123")) {
		return EXIT_FAILURE;
	}


	return EXIT_SUCCESS;
}
