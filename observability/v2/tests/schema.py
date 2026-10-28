"""A JSON Schema validator for the keywords metrics/contract.schema.json uses, in the Python standard library.

A schema keyword this module does not implement is an error, never ignored: a schema that grows a keyword fails
the tests until the keyword is implemented here (and tested in test_schema.py).
"""
import re

ANNOTATIONS = {"$schema", "$id", "title", "description"}
TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


class SchemaError(Exception):
    """The schema uses a keyword this validator does not implement."""


def _unique(items):
    seen = []
    for item in items:
        if any(item == other and type(item) is type(other) for other in seen):
            return False
        seen.append(item)
    return True


def validate(instance, schema, path="$"):
    """The list of errors, each "<path>: <what is wrong>"; empty when instance is valid."""
    errors = []
    unknown = set(schema) - ANNOTATIONS - set(_KEYWORDS)
    if unknown:
        raise SchemaError(f"{path}: keywords not implemented: {sorted(unknown)}")
    for keyword, check in _KEYWORDS.items():
        if keyword in schema:
            errors += check(instance, schema[keyword], schema, path)
    return errors


def _type(value, expected, _schema, path):
    names = expected if isinstance(expected, list) else [expected]
    if not any(TYPES[name](value) for name in names):
        return [f"{path}: {value!r:.60} is not of type {expected}"]
    return []


def _const(value, expected, _schema, path):
    return [] if value == expected and type(value) is type(expected) else [f"{path}: must be {expected!r}"]


def _enum(value, allowed, _schema, path):
    return [] if value in allowed else [f"{path}: {value!r} is not one of {allowed}"]


def _pattern(value, pattern, _schema, path):
    if isinstance(value, str) and not re.search(pattern, value):
        return [f"{path}: {value!r} does not match {pattern}"]
    return []


def _min_length(value, minimum, _schema, path):
    if isinstance(value, str) and len(value) < minimum:
        return [f"{path}: shorter than {minimum} characters"]
    return []


def _minimum(value, minimum, _schema, path):
    if TYPES["number"](value) and value < minimum:
        return [f"{path}: {value} is less than {minimum}"]
    return []


def _maximum(value, maximum, _schema, path):
    if TYPES["number"](value) and value > maximum:
        return [f"{path}: {value} is more than {maximum}"]
    return []


def _required(value, names, _schema, path):
    if isinstance(value, dict):
        return [f"{path}: {name!r} is required" for name in names if name not in value]
    return []


def _min_properties(value, minimum, _schema, path):
    if isinstance(value, dict) and len(value) < minimum:
        return [f"{path}: fewer than {minimum} properties"]
    return []


def _properties(value, properties, _schema, path):
    if not isinstance(value, dict):
        return []
    return [e for name, sub in properties.items() if name in value for e in validate(value[name], sub, f"{path}.{name}")]


def _pattern_properties(value, patterns, _schema, path):
    if not isinstance(value, dict):
        return []
    return [e for name, item in value.items() for pattern, sub in patterns.items() if re.search(pattern, name)
            for e in validate(item, sub, f"{path}.{name}")]


def _additional_properties(value, additional, schema, path):
    if not isinstance(value, dict):
        return []
    declared = set(schema.get("properties", {}))
    patterns = list(schema.get("patternProperties", {}))
    extra = [name for name in value if name not in declared and not any(re.search(p, name) for p in patterns)]
    if additional is False:
        return [f"{path}: property {name!r} is not allowed" for name in extra]
    if isinstance(additional, dict):
        return [e for name in extra for e in validate(value[name], additional, f"{path}.{name}")]
    return []


def _dependent_required(value, dependencies, _schema, path):
    if not isinstance(value, dict):
        return []
    return [f"{path}: {name!r} needs {needed!r}" for name, needs in dependencies.items() if name in value
            for needed in needs if needed not in value]


def _items(value, sub, _schema, path):
    if not isinstance(value, list):
        return []
    return [e for i, item in enumerate(value) for e in validate(item, sub, f"{path}[{i}]")]


def _min_items(value, minimum, _schema, path):
    if isinstance(value, list) and len(value) < minimum:
        return [f"{path}: fewer than {minimum} items"]
    return []


def _max_items(value, maximum, _schema, path):
    if isinstance(value, list) and len(value) > maximum:
        return [f"{path}: more than {maximum} items"]
    return []


def _unique_items(value, unique, _schema, path):
    if unique and isinstance(value, list) and not _unique(value):
        return [f"{path}: items are not unique"]
    return []


_KEYWORDS = {
    "type": _type, "const": _const, "enum": _enum, "pattern": _pattern, "minLength": _min_length,
    "minimum": _minimum, "maximum": _maximum, "required": _required, "minProperties": _min_properties,
    "properties": _properties, "patternProperties": _pattern_properties,
    "additionalProperties": _additional_properties, "dependentRequired": _dependent_required, "items": _items,
    "minItems": _min_items, "maxItems": _max_items, "uniqueItems": _unique_items,
}
