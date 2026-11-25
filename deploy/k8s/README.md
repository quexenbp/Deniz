# Kubernetes

`deniz.yaml` is a single-namespace example: API deployment, two monitor
workers, a PVC, a daily backup CronJob and a Service. It assumes an external
Postgres; point `DENIZ_DB_URL` at it before applying.

```bash
kubectl apply -f deploy/k8s/deniz.yaml
kubectl -n deniz create secret generic deniz --from-literal=DENIZ_API_TOKEN=... --from-literal=DENIZ_DB_URL=... --dry-run=client -o yaml | kubectl apply -f -
```

Notes:

- The worker replicas are safe because `monitor daemon` claims due monitors
  with a Postgres lease; two replicas do not run the same monitor twice.
- The API is read-mostly; terminate TLS at an ingress. The bearer token is the
  only auth layer.
- Scale workers by editing `replicas`; ingest is bounded by provider rate
  limits, not by pod count.
- Keep `DENIZ_HOME` on the PVC and enable `runs prune` plus `case prune` in a
  CronJob for retention.
- The image runs as UID 10001. A read-only root filesystem needs an emptyDir at
  `/tmp` and `/data` writable.
