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

	if (!compare_hash("argon2i13-3-1048576-27b0714c1fcb395efd9742f7800e90797fc916b44370d42e21f9523f8d96e647", "fsmaxb@1984not.de")) {
		return EXIT_FAILURE;
	}
	if (!compare_hash("argon2i13-3-1048576-61e6107159dee562f112fafee077d38f21bcf2a63084ff967a91d2e08eef1193", "+19995550123")) {
		return EXIT_FAILURE;
	}


	return EXIT_SUCCESS;
}
