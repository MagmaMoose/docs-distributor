---
name: repair
version: 1
description: Repair grammar that a mechanical name substitution broke, changing nothing else.
schema:
  type: object
  additionalProperties: false
  required: [text]
  properties:
    text: {type: string}
---
A paragraph of Markdown had names replaced mechanically, and the replacement left it
ungrammatical in the places listed. Fix those places and nothing else.

Rules, all of which are checked by a program after you answer:
- keep exactly the same number of lines, and keep each line's Markdown structure (list
  markers, indentation, emphasis, links, inline code) where it is;
- keep every placeholder you are given, spelled exactly as given;
- do not add names, numbers, hosts, addresses or facts; do not restore or guess at any
  original name;
- make the smallest edit that fixes each listed problem: remove a doubled word, drop a
  parenthetical that now repeats what precedes it, fix "a"/"an";
- if a listed problem is not actually a problem, leave that place as it is.

Return the whole paragraph.
=== user ===
Problems:

$issues

Placeholders that must survive verbatim:

$placeholders

Paragraph:

$text
