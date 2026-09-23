# Operations runbook

## Rotating example-org keys

Run the rotation job against an example-org cluster, one context at a time:

```bash
kubectl --context cluster-prd -n ops create job rotate --from=cronjob/rotate
```

Read [the network page](../networking/example-org-network.md) first.
