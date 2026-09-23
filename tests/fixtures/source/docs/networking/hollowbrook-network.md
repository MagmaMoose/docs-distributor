# Hollowbrook network

Subscription `7c1e4b9a-3f2d-4e8b-9a6c-5d2f1e0b8a47` holds the hub VNet. The edge
gateway answers on 93.184.216.34 and routes 10.20.0.0/16 to Zuidmeer.

```text
├── hb-prd-west/            # production, Brackenfold DC1
├── hb-acc/                 # acceptance
└── shared/                 # peering and DNS
```

Security Gate (Chargewall) scans every change before it merges.
