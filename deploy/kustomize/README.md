# Kubernetes example deployment

Get a starting config from the binary by passing a new file path:

```sh
./guassp ./guassp.yaml
```

The command writes an example and exits.
You can also download the [example config from the repository][config].
Save it as `deploy/kustomize/guassp.yaml` and edit it.
Keep the token placeholders `${GITLAB_TOKEN:?set GITLAB_TOKEN}`
and `${SONARQUBE_TOKEN:?set SONARQUBE_TOKEN}`;
Guassp expands them from the Secret environment variables below.

Create `deploy/kustomize/kustomization.yaml` next to `guassp.yaml`:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - github.com/WoozyMasta/guassp//deploy/kustomize/base?ref=master

configMapGenerator:
  - name: guassp-config
    files:
      - guassp.yaml

components:
  # - github.com/WoozyMasta/guassp//deploy/kustomize/components/ingress?ref=master
  # - github.com/WoozyMasta/guassp//deploy/kustomize/components/gateway?ref=master

buildMetadata: [managedByLabel]
```

Kustomize generates the ConfigMap from `guassp.yaml`
and mounts it in the container as `/config/guassp.yaml`.
Its generated name includes a content hash,
so changing the config updates the Deployment reference automatically.

Optionally create a namespace.
Create a Secret with the tokens used by the example config:

```sh
kubectl create namespace guassp
kubectl create secret generic guassp-secrets -n guassp \
  --from-literal=GITLAB_TOKEN='your-gitlab-token' \
  --from-literal=SONARQUBE_TOKEN='your-sonarqube-token'
```

For protected metrics, also add `METRICS_TOKEN` or both
`METRICS_USERNAME` and `METRICS_PASSWORD` to the Secret,
and configure the matching `metrics` fields. Choose one authentication method.

To protect the JSON API, optionally add `GUASSP_API_TOKEN` to the Secret
and set `api.token` in `guassp.yaml`.

Apply the Kustomization, using the namespace if you created one:

```sh
kubectl apply -k deploy/kustomize -n guassp
```

[config]: ../../internal/config/generated/guassp.example.yaml
