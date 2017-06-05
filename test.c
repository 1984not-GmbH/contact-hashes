/*
 * contact-hashes, Calculating a hash from phone number or email addresses
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
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
	if (!compare_hash("argon2i13-3-10485760-8744a5b8c8530ec271356f36e346953ab7a212a0a8a009c4d88a04baafa0fb2f", "fsmaxb@1984not.de")) {
		return EXIT_FAILURE;
	}
	if (!compare_hash("argon2i13-3-10485760-ca6de2c0dbe5f4c1e89c5a36714bc6284566bf5e6e5ef1c255ded18aa1522c5e", "+19995550123")) {
		return EXIT_FAILURE;
	}

	// test a scenario with 200 contacts with email address and phone number
	for (size_t i = 0; i < 400; i++) {
		char contact[] = "test-contact";
		char *hash = hash_contact(contact, sizeof(contact));
		if (hash == NULL) {
			return EXIT_FAILURE;
		}
		free(hash);
	}

	return EXIT_SUCCESS;
}
