"""The account name: what a person signs in with.

An account name is a short, lower-case label: 3 to 32 characters, letters and digits plus `.`, `_` and `-`, starting and ending with a letter or digit, and NO `@` (so a string with an `@` is always recognisably an email). It is unique across the whole
platform (compared case-insensitively, by the same rule as email addresses: app/core/emails.py) and is not an email address: nothing about it needs to be verified or delivered to.
"""
import re

ACCOUNT_NAME_PATTERN = r"^[a-z0-9][a-z0-9._-]{1,30}[a-z0-9]$"  # 3-32 characters; the same shape the database enforces (migration 071)
_VALID = re.compile(ACCOUNT_NAME_PATTERN)
MAX_LENGTH = 32
MIN_LENGTH = 3
FALLBACK = "user"

RULES = "An account name is 3 to 32 characters: lower-case letters, digits, '.', '_' or '-', starting and ending with a letter or digit."


class InvalidAccountName(ValueError):
    pass


def normalize_account_name(name: str) -> str:
    """The name as it is compared and stored: trimmed and lower-cased."""
    return name.strip().lower()


def is_valid_account_name(name: str) -> bool:
    return bool(_VALID.match(name))


def validate_account_name(name: str) -> str:
    """The normalised name, or InvalidAccountName with the rule."""
    normalised = normalize_account_name(name)
    if not _VALID.match(normalised):
        raise InvalidAccountName(RULES)
    return normalised


def looks_like_email(identifier: str) -> bool:
    """A sign-in identifier with an `@` is an email: an account name can never contain one."""
    return "@" in identifier


def _trim_edges(text: str) -> str:
    return re.sub(r"^[^a-z0-9]+|[^a-z0-9]+$", "", text)


def suggest_account_name(source: str) -> str:
    """A valid account name made from free text or an email address (its part before the `@`): lower-cased, anything not allowed becomes `-`, trimmed to the rules. Never empty and never shorter than 3: falls back to `user`.
    It is only a suggestion: it may already be taken (see app.services.account_names.unique_account_name)."""
    local = source.split("@", 1)[0].strip().lower()
    cleaned = _trim_edges(re.sub(r"[^a-z0-9._-]+", "-", local))
    cleaned = _trim_edges(cleaned[:MAX_LENGTH])
    return cleaned if len(cleaned) >= MIN_LENGTH else FALLBACK


def with_suffix(base: str, n: int) -> str:
    """`base-n`, shortened so the whole stays within the limit and still ends in a letter or digit."""
    suffix = f"-{n}"
    return _trim_edges(base[: MAX_LENGTH - len(suffix)]) + suffix
