---
name: place
version: 1
description: Choose where a page the source nav does not list belongs in the generated nav.
schema:
  type: object
  additionalProperties: false
  required: [placements]
  properties:
    placements:
      type: array
      items:
        type: object
        additionalProperties: false
        required: [path, section, title]
        properties:
          path: {type: string}
          section:
            type: array
            items: {type: string}
          title: {type: string, maxLength: 60}
---
You place documentation pages in an existing navigation tree. Each page below exists in
the documentation but is not listed in its navigation. Choose, for each, the existing
section it most naturally belongs to, as the list of section titles from the top of the
tree down, and a short title for its nav entry.

- Use only sections that exist in the tree you are given; an empty list means the top level
  of this documentation set.
- Base the title on the page's own heading, shortened if it is long. Do not add names,
  products or facts that are not in the heading.
=== user ===
Navigation tree (section titles, indented by depth):

$tree

Pages to place:

$pages
