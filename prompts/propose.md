---
name: propose
version: 1
description: Propose a placeholder for each sensitive term, extending the published scheme.
schema:
  type: object
  additionalProperties: false
  required: [proposals]
  properties:
    proposals:
      type: array
      items:
        type: object
        additionalProperties: false
        required: [term, class, to, reason]
        properties:
          term: {type: string}
          class:
            type: string
            enum: [org, repo, domain, host, url, person, handle, email, customer, vendor, product, project, account, subscription, tenant, uuid, ip, cidr, path, cluster, namespace, secret, location, other]
          to: {type: string, maxLength: 80}
          reason: {type: string, maxLength: 200}
---
You choose stand-ins for names that are being removed from documentation before it is
published. The published corpus already uses a placeholder scheme, and every stand-in you
propose must fit it so the corpus stays coherent:

- use the next unused value of an existing series where the term's class has one
  (customers are client-a, client-b, ...; vendors vendor-A, vendor-B, ...; people's
  handles engineer-a, engineer-b, ...);
- domains live under example.com, example.net, example.org or example.io, never under a
  real top-level domain someone could register;
- addresses come from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 or private ranges;
- an internal system gets a short descriptive name for what it does ("ticket bridge",
  "billing-api"), not a joke and not a near-spelling of the original;
- a stand-in never contains the original term, any part of it, or an obvious
  abbreviation of it;
- keep the stand-in's shape close to how the original is used: a hostname stays a
  hostname, a lower-case identifier stays lower-case and hyphenated.

Never reuse a value from "already taken" for a different term.
=== user ===
The scheme in use, class by class:

$vocabulary

Already taken (do not reuse for a different term):

$taken

Propose one stand-in for each of these sensitive terms:

$terms
