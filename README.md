Contact Hashes
==============

Library that calculates a password hash for email addresses and telephone numbers so that the contact data can be stored in a database for contact lookup.

The hash function is Argon2id.

Note that phone numbers and email addresses need to be normalized for this to work.

It contains one C function (see `contact-hashes.h`) and a command line interface that takes data from stdin and prints the hash to stdout (`chash`).
