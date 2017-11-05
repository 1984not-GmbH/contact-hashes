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
#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include "contact-hashes.h"

static const size_t default_buffer_size = 1024;

static char *grow_buffer(char *buffer, size_t *size) {
	assert(((buffer != NULL) && (size != NULL)) || "One of the arguments was a NULL pointer.");

	size_t old_size = *size;
	*size = 2 * old_size;
	char *new_buffer = malloc(*size);
	assert((new_buffer != NULL) || "Memory allocation failed.");

	memcpy(new_buffer, buffer, old_size);
	free(buffer);

	return new_buffer;
}

int main(void) {
	size_t buffer_size = default_buffer_size;
	char *buffer = malloc(buffer_size);

	size_t content_length = 0;
	size_t read_bytes = 0;
	do {
		read_bytes = fread(buffer + content_length, 1, buffer_size - content_length, stdin);
		if (read_bytes == (buffer_size - content_length)) {
			buffer = grow_buffer(buffer, &buffer_size);
		}
		content_length += read_bytes;
	} while (read_bytes > 0);
	if (!feof(stdin)) {
		assert(false || "Input error.");
	}

	char *hash = hash_contact(buffer, content_length);
	assert((hash != NULL) || "Failed to calculate the hash.");
	free(buffer);

	puts(hash);
	free(hash);

	return EXIT_SUCCESS;
}
