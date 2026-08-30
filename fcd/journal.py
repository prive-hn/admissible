"""Immutable JSON-shaped journal records and replay ingress.

Admissible's language-neutral event contract is a JSON object. ``JournalEvent``
implements the read-only mapping interface (indexing, ``get``, iteration and
mapping equality) while making the complete object graph immutable. Consumers
crossing a JSON/schema boundary use :func:`to_plain_json` for a detached plain
representation. Replay accepts legacy plain ``dict`` records, but canonicalizes
them before any event discriminator, id, or other journal value is compared.
"""
from __future__ import annotations

import json
import math
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

__all__ = [
    "FrozenJSONDict",
    "FrozenJSONList",
    "JournalEvent",
    "JournalValueError",
    "ReplayError",
    "canonical_json",
    "normalize_journal",
    "to_plain_json",
]

_FIXED_VALUE_ERROR = "journal event must contain canonical JSON values"
_FIXED_REPLAY_ERROR = "replay refused: journal must contain canonical events"


class JournalValueError(ValueError):
    """A value cannot be represented by the closed canonical JSON domain."""


class ReplayError(ValueError):
    """Replay input is not a canonical sequence of journal events."""


class FrozenJSONDict(tuple, Mapping[str, Any]):
    """A reflection-resistant immutable JSON object backed by a C tuple."""

    __slots__ = ()

    def __new__(cls, values: tuple[tuple[str, Any], ...] = ()):
        return tuple.__new__(cls, values)

    def __getitem__(self, key: Any) -> Any:
        if type(key) is not str:
            raise KeyError(key)
        for candidate, value in tuple.__iter__(self):
            if candidate == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _ in tuple.__iter__(self))

    def __len__(self) -> int:
        return tuple.__len__(self)

    def __contains__(self, key: object) -> bool:
        return type(key) is str and any(
            candidate == key for candidate, _ in tuple.__iter__(self))

    def __repr__(self) -> str:
        return repr({key: value for key, value in tuple.__iter__(self)})

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mapping):
            return dict(self.items()) == dict(other.items())
        return False

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


class FrozenJSONList(tuple, Sequence[Any]):
    """An immutable JSON array that compares equal to lists and tuples."""

    __slots__ = ()

    def __new__(cls, values: tuple[Any, ...] = ()):
        return tuple.__new__(cls, values)

    def __repr__(self) -> str:
        return repr(list(tuple.__iter__(self)))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Sequence) and not isinstance(
                other, (str, bytes, bytearray)):
            return list(tuple.__iter__(self)) == list(other)
        return False

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def _freeze_json(value: Any, seen: set[int] | None = None) -> Any:
    value_type = type(value)
    if value is None or value_type in (bool, int):
        return value
    if value_type is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise JournalValueError(_FIXED_VALUE_ERROR) from None
        return value
    if value_type is float:
        if math.isfinite(value):
            return value
        raise JournalValueError(_FIXED_VALUE_ERROR)
    if value_type in (FrozenJSONDict, JournalEvent, FrozenJSONList):
        # Tuple-backed public values can be manufactured with ``tuple.__new__``.
        # Revalidate their complete graph at every trust boundary instead of
        # treating exact runtime type as proof of canonical construction.
        return _freeze_json(to_plain_json(value), seen)
    if value_type not in (dict, list, tuple):
        raise JournalValueError(_FIXED_VALUE_ERROR)

    active = set() if seen is None else seen
    identity = id(value)
    if identity in active:
        raise JournalValueError(_FIXED_VALUE_ERROR)
    active.add(identity)
    try:
        if value_type is dict:
            items: list[tuple[str, Any]] = []
            for key, child in dict.items(value):
                if type(key) is not str:
                    raise JournalValueError(_FIXED_VALUE_ERROR)
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError:
                    raise JournalValueError(_FIXED_VALUE_ERROR) from None
                items.append((key, _freeze_json(child, active)))
            return FrozenJSONDict(tuple(items))
        return FrozenJSONList(tuple(_freeze_json(child, active) for child in value))
    finally:
        active.remove(identity)


class JournalEvent(FrozenJSONDict):
    """One deeply immutable event with the existing mapping field shape."""

    __slots__ = ()

    def __new__(cls, event: Mapping[str, Any]):
        try:
            event_type = type(event)
            if event_type is JournalEvent:
                event = to_plain_json(event)
                event_type = dict
            if event_type is not dict:
                raise JournalValueError(_FIXED_VALUE_ERROR)
            frozen = _freeze_json(event)
        except RecursionError:
            raise JournalValueError(_FIXED_VALUE_ERROR) from None
        return tuple.__new__(cls, tuple(tuple.__iter__(frozen)))


def _to_plain_json(value: Any, _seen: set[int] | None = None) -> Any:
    """Return a detached plain ``dict``/``list`` JSON representation."""

    value_type = type(value)
    if value is None or value_type in (bool, int):
        return value
    if value_type is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise JournalValueError(_FIXED_VALUE_ERROR) from None
        return value
    if value_type is float:
        if math.isfinite(value):
            return value
        raise JournalValueError(_FIXED_VALUE_ERROR)
    if value_type not in (
        FrozenJSONDict, JournalEvent, dict, FrozenJSONList, tuple, list
    ):
        raise JournalValueError(_FIXED_VALUE_ERROR)

    active = set() if _seen is None else _seen
    identity = id(value)
    if identity in active:
        raise JournalValueError(_FIXED_VALUE_ERROR)
    active.add(identity)
    try:
        if value_type in (FrozenJSONDict, JournalEvent):
            plain = {}
            for pair in tuple.__iter__(value):
                if type(pair) is not tuple or len(pair) != 2:
                    raise JournalValueError(_FIXED_VALUE_ERROR)
                key, child = pair
                if type(key) is not str:
                    raise JournalValueError(_FIXED_VALUE_ERROR)
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError:
                    raise JournalValueError(_FIXED_VALUE_ERROR) from None
                plain[key] = _to_plain_json(child, active)
            return plain
        if value_type is dict:
            plain = {}
            for key, child in dict.items(value):
                if type(key) is not str:
                    raise JournalValueError(_FIXED_VALUE_ERROR)
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError:
                    raise JournalValueError(_FIXED_VALUE_ERROR) from None
                plain[key] = _to_plain_json(child, active)
            return plain
        iterator = tuple.__iter__(value) if value_type is FrozenJSONList else iter(value)
        return [_to_plain_json(child, active) for child in iterator]
    finally:
        active.remove(identity)


def to_plain_json(value: Any, _seen: set[int] | None = None) -> Any:
    """Return detached JSON values, refusing excessive nesting uniformly."""

    try:
        return _to_plain_json(value, _seen)
    except RecursionError:
        raise JournalValueError(_FIXED_VALUE_ERROR) from None


def canonical_json(value: Any) -> str:
    """Canonical UTF-8 JSON text for a canonical journal value."""

    try:
        frozen = _freeze_json(value)
    except RecursionError:
        raise JournalValueError(_FIXED_VALUE_ERROR) from None
    return json.dumps(
        to_plain_json(frozen),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def normalize_journal(journal: object) -> tuple[JournalEvent, ...]:
    """Canonicalize a legacy list/tuple before replay reads any field."""

    if type(journal) not in (list, tuple):
        raise ReplayError(_FIXED_REPLAY_ERROR)
    normalized: list[JournalEvent] = []
    try:
        for event in journal:  # exact list/tuple iteration has no foreign hook
            if type(event) is JournalEvent:
                normalized.append(JournalEvent(event))
            elif type(event) is dict:
                normalized.append(JournalEvent(event))
            else:
                raise JournalValueError(_FIXED_VALUE_ERROR)
    except (JournalValueError, RecursionError, TypeError, ValueError, OverflowError):
        raise ReplayError(_FIXED_REPLAY_ERROR) from None
    return tuple(normalized)
