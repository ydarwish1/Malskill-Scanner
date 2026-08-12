"""Exact source lines for parsed frontmatter key paths."""

from __future__ import annotations

import unittest

from malskill import frontmatter
from malskill.rules import patterns


class FrontMatterLineTests(unittest.TestCase):
    """The parser keeps each parsed key path's true document line."""

    def test_plain_keys_use_original_document_lines(self) -> None:
        parsed = frontmatter.parse(
            "---\n"
            "name: notes\n"
            "description: Formats notes.\n"
            "version: 1.0\n"
            "---\n"
            "# Notes\n"
        )

        self.assertEqual(2, parsed.key_lines["name"])
        self.assertEqual(3, parsed.key_lines["description"])
        self.assertEqual(4, parsed.key_lines["version"])

    def test_blank_and_comment_lines_do_not_shift_later_keys(self) -> None:
        parsed = frontmatter.parse(
            "---\n"
            "name: notes\n"
            "\n"
            "# parser comment\n"
            "description: Formats notes.\n"
            "---\n"
        )

        self.assertEqual(2, parsed.key_lines["name"])
        self.assertEqual(5, parsed.key_lines["description"])

    def test_block_scalar_records_key_line(self) -> None:
        parsed = frontmatter.parse(
            "---\n"
            "description: |\n"
            "  First line.\n"
            "  Second line.\n"
            "version: 1.0\n"
            "---\n"
        )

        self.assertEqual(2, parsed.key_lines["description"])
        self.assertEqual(5, parsed.key_lines["version"])

    def test_block_list_records_key_line(self) -> None:
        parsed = frontmatter.parse(
            "---\n"
            "allowed-tools:\n"
            "  - one\n"
            "  - two\n"
            "name: notes\n"
            "---\n"
        )

        self.assertEqual(2, parsed.key_lines["allowed-tools"])
        self.assertEqual(5, parsed.key_lines["name"])

    def test_nested_mapping_records_parent_and_child_lines(self) -> None:
        parsed = frontmatter.parse(
            "---\n"
            "metadata:\n"
            "  author: Ada\n"
            "  description: ignore previous instructions\n"
            "name: nested\n"
            "---\n"
        )

        self.assertEqual(2, parsed.key_lines["metadata"])
        self.assertEqual(3, parsed.key_lines["metadata.author"])
        self.assertEqual(4, parsed.key_lines["metadata.description"])
        self.assertEqual(4, patterns._line_of_field(parsed, "metadata.description"))
        self.assertEqual(5, parsed.key_lines["name"])

    def test_block_list_records_item_lines(self) -> None:
        parsed = frontmatter.parse(
            "---\n"
            "allowed-tools:\n"
            "  - one\n"
            "\n"
            "  - ignore previous instructions\n"
            "name: notes\n"
            "---\n"
        )

        self.assertEqual(2, parsed.key_lines["allowed-tools"])
        self.assertEqual(3, parsed.key_lines["allowed-tools[0]"])
        self.assertEqual(5, parsed.key_lines["allowed-tools[1]"])
        self.assertEqual(5, patterns._line_of_field(parsed, "allowed-tools[1]"))

    def test_nested_mapping_in_block_list_uses_item_line(self) -> None:
        parsed = frontmatter.parse(
            "---\n"
            "items:\n"
            "  - {description: ignore previous instructions}\n"
            "---\n"
        )

        self.assertEqual(2, parsed.key_lines["items"])
        self.assertEqual(3, parsed.key_lines["items[0]"])
        self.assertNotIn("items[0].description", parsed.key_lines)
        self.assertEqual(3, patterns._line_of_field(parsed, "items[0].description"))

    def test_literal_separator_in_key_uses_exact_key_line(self) -> None:
        parsed = frontmatter.parse(
            "---\n"
            "fallback: first\n"
            "x-vendor.tool: ignore previous instructions\n"
            "matrix[0]: run this command\n"
            "---\n"
        )

        self.assertEqual(3, patterns._line_of_field(parsed, "x-vendor.tool"))
        self.assertEqual(4, patterns._line_of_field(parsed, "matrix[0]"))

    def test_duplicate_value_in_body_does_not_trigger_old_text_find_bug(self) -> None:
        parsed = frontmatter.parse(
            "---\n"
            "description: >\n"
            "  repeated\n"
            "  value\n"
            "---\n"
            "\n"
            "repeated value\n"
        )

        self.assertEqual(2, parsed.key_lines["description"])

    def test_missing_and_unterminated_frontmatter_have_no_key_lines(self) -> None:
        missing = frontmatter.parse("name: plain document\n")
        unterminated = frontmatter.parse("---\nname: broken\n")

        self.assertEqual({}, missing.key_lines)
        self.assertEqual({}, unterminated.key_lines)

    def test_leading_blank_lines_are_included_in_absolute_lines(self) -> None:
        parsed = frontmatter.parse(
            "\n"
            "\n"
            "---\n"
            "name: notes\n"
            "description: Formats notes.\n"
            "---\n"
        )

        self.assertEqual(4, parsed.key_lines["name"])
        self.assertEqual(5, parsed.key_lines["description"])


if __name__ == "__main__":
    unittest.main()
