"""One definition of "the same email address".

An email address is an identifier here (login is by email alone), and `Alice@Example.com` and `alice@example.com` are the same mailbox for every real mail system. They used to be two different accounts: the unique constraint
on `users.email` is case-sensitive, so both could exist, login matched the exact text, and the duplicate-address check that keeps one organisation from claiming another's address could be bypassed by changing a letter's case.

Every address is compared by `normalize_email` (trimmed and lower-cased), and stored in that form when an account is created. Existing rows are NOT rewritten: they are found by comparing `lower(email)`, so a legacy
mixed-case account still signs in, and a unique index on `lower(email)` (migration 070) stops a new case-variant being added.
"""


def normalize_email(email: str) -> str:
    """The address as it is compared and stored: trimmed and lower-cased."""
    return email.strip().lower()
