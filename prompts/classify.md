---
name: classify
# Bump to deliberately invalidate every cached classification made with this template.
version: 1
description: Decide, per unmapped term, whether publishing it would help identify the source.
schema:
  type: object
  additionalProperties: false
  required: [results]
  properties:
    results:
      type: array
      items:
        type: object
        additionalProperties: false
        required: [term, sensitive, category, reason]
        properties:
          term: {type: string}
          sensitive: {type: boolean}
          category:
            type: string
            enum:
              - organisation
              - customer
              - person
              - internal-system
              - vendor
              - location
              - resource-name
              - public-technology
              - public-organisation
              - generic-word
              - other
          reason: {type: string, maxLength: 200}
---
You review terms found in internal engineering documentation that is about to be published
with the organisation's identity removed. The mapping has already replaced every name it
knows. Each term below survived that pass. Decide, for each one, whether publishing it
would help a reader work out WHICH organisation, customer, person, site or internal system
the documentation describes.

Sensitive (true):
- the organisation, its subsidiaries, departments, teams or brand names;
- customers, tenants, clients, partners and the sites or places they are in;
- people: names, initials, handles, usernames, mailbox local parts;
- internal system, product, project or service names and codenames, including invented
  compound identifiers (storage account names, cluster names, resource-group names,
  subscription or project nicknames);
- a vendor or supplier small or regional enough that naming it narrows the field;
- words in a local language that reveal the country or sector when they appear in
  otherwise English text.

Not sensitive (false):
- public software, protocols, cloud services, file formats and standards used by
  thousands of organisations (Kubernetes, Traefik, Azure, OIDC, YAML);
- large public organisations and vendors whose mention narrows nothing (Microsoft,
  Cloudflare, GitHub);
- ordinary words, inflections, abbreviations and command names, in any language that
  does not narrow the field.

When the context does not settle it, answer sensitive. A wrong "sensitive" costs a person a
minute; a wrong "not sensitive" publishes a name.

Answer for every term, exactly once, spelled exactly as given. Keep each reason under 200
characters and do not repeat the term's surroundings in it.
=== user ===
Classify each term. Contexts are excerpts from the pages it appears in, already anonymised
apart from the term itself.

$terms
