"""Each keyword of schema.py accepts what it should and refuses what it should."""
import unittest

import schema


class SchemaKeywords(unittest.TestCase):
    def ok(self, instance, sub):
        self.assertEqual(schema.validate(instance, sub), [])

    def bad(self, instance, sub):
        self.assertNotEqual(schema.validate(instance, sub), [], f"{instance!r} passed {sub}")

    def test_type(self):
        self.ok(1, {"type": "integer"})
        self.bad(True, {"type": "integer"})
        self.bad(1.5, {"type": "integer"})
        self.ok("x", {"type": ["string", "null"]})
        self.bad([], {"type": "object"})

    def test_const_and_enum(self):
        self.ok(2, {"const": 2})
        self.bad(True, {"const": 1})
        self.ok("a", {"enum": ["a", "b"]})
        self.bad("c", {"enum": ["a", "b"]})

    def test_strings(self):
        self.ok("cmtc-v2-dns", {"pattern": "^cmtc-v2-[a-z-]+$"})
        self.bad("cmtc-dns", {"pattern": "^cmtc-v2-[a-z-]+$"})
        self.ok("abcd", {"minLength": 4})
        self.bad("abc", {"minLength": 4})

    def test_numbers(self):
        self.ok(1, {"minimum": 1})
        self.bad(0, {"minimum": 1})
        self.ok(5, {"maximum": 5})
        self.bad(6, {"maximum": 5})

    def test_objects(self):
        sub = {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}},
               "additionalProperties": False}
        self.ok({"a": "x"}, sub)
        self.bad({}, sub)
        self.bad({"a": 1}, sub)
        self.bad({"a": "x", "b": 1}, sub)
        self.ok({"x": 1}, {"minProperties": 1})
        self.bad({}, {"minProperties": 1})

    def test_pattern_and_additional_properties(self):
        sub = {"patternProperties": {"^OP[0-9]$": {"type": "string"}}, "additionalProperties": False}
        self.ok({"OP1": "x"}, sub)
        self.bad({"OP1": 1}, sub)
        self.bad({"XX": "x"}, sub)
        self.ok({"k": "v"}, {"additionalProperties": {"type": "string"}})
        self.bad({"k": 1}, {"additionalProperties": {"type": "string"}})

    def test_dependent_required(self):
        sub = {"dependentRequired": {"line": ["token"]}}
        self.ok({"line": 1, "token": "x"}, sub)
        self.ok({}, sub)
        self.bad({"line": 1}, sub)

    def test_arrays(self):
        self.ok([1, 2], {"items": {"type": "integer"}, "minItems": 2, "maxItems": 2, "uniqueItems": True})
        self.bad([1, "2"], {"items": {"type": "integer"}})
        self.bad([1], {"minItems": 2})
        self.bad([1, 2, 3], {"maxItems": 2})
        self.bad([1, 1], {"uniqueItems": True})
        self.ok([1, True], {"uniqueItems": True})

    def test_unknown_keyword_is_an_error(self):
        with self.assertRaises(schema.SchemaError):
            schema.validate(1, {"oneOf": []})

    def test_errors_name_the_path(self):
        errors = schema.validate({"a": [{"b": 1}]}, {"properties": {"a": {"items": {"properties": {
            "b": {"type": "string"}}}}}})
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("$.a[0].b:"), errors)


if __name__ == "__main__":
    unittest.main()
