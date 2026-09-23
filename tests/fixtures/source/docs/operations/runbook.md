# Operations runbook

## Rotating Hollowbrook keys

Run the rotation job against a Hollowbrook cluster, one context at a time:

```bash
kubectl --context hb-prd-west -n ops create job rotate --from=cronjob/rotate
```

Read [the network page](../networking/hollowbrook-network.md) first.
