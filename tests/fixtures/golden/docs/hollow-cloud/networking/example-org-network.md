# example-org network

Subscription `aaaaaaaa-1111-2222-3333-aaaaaaaaaaaa` holds the hub VNet. The edge
gateway answers on 203.0.113.10 and routes 10.20.0.0/16 to client-j.

```text
├── cluster-prd/            # production, vendor-C DC1
├── cluster-acceptance/     # acceptance
└── shared/                 # peering and DNS
```

Security Gate scans every change before it merges.
