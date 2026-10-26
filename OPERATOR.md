# Operator notes: dkim2_intelligence

## Artifact chain

Every deployment of `dkim2-intelligence.so` requires one matching set of:

- `dkim2-intelligence.so`;
- `dkim2-intelligence.so.sha256`;
- `dkim2-intelligence.so.minisig`;
- `dkim2-intelligence.so.provenance`;
- the exact `checksum` pin in the module configuration.

The artifact is ABI-bound to one core release. Its provenance must name the
same core commit, Go version, `GOEXPERIMENT=runtimesecret` and `netgo` tags as
the running Nauthilus image. A core upgrade always needs a rebuild with
`CORE_REF` set to the new tag, a new checksum and a new signature.

## Moving from the bundled to the external artifact

Up to core `v4.0.1` the core image built and signed this plugin with the core
build key (`nauthilus-plugin-build-key-2026`) into
`/usr/local/lib/nauthilus/plugins/dkim2-intelligence.so`. As an external
plugin it is built here and signed with the deployment-owned key (default
`SIGNING_KEY`, the same key used for `rns_auth`). The module entry in
`55-go-plugins.yml` therefore changes as follows:

| Field | Bundled (core <= v4.0.1) | External |
|-------|--------------------------|----------|
| `path` | `/usr/local/lib/nauthilus/plugins/dkim2-intelligence.so` (image) | same path, provided by a read-only `subPath` mount of the private-plugin PVC generation |
| `checksum` | core image build | `sha256:` value from `build/dkim2-intelligence.so.sha256` |
| `signature` | `minisign:/usr/local/lib/nauthilus/plugins/dkim2-intelligence.so.minisig` | same path, mounted next to the artifact |
| `signer` | `nauthilus-plugin-build-key-2026` | `rns-auth-plugin-build-key-2026` (must exist in `plugins.trust.signers`) |
| `config` | unchanged | unchanged (`decision_profile`, `geoip_provider`, `reputation_fact`, `reputation_provider`, optional `identity_contracts`, `signer_sets`) |

The `name: dkim2_intelligence` and `type: go` stay unchanged, so Policy
provider references (`module: dkim2_intelligence`, component `assessment`)
need no change for the move itself.

If a core image still bundles its own copy at the same path, the mount
replaces it; the checksum and signer pin make sure the intended artifact is
loaded. Never relax `verification_policy: signature_required` to proceed.

## Rollout

1. `make check CORE_REF=<tag>` and `make sign CORE_REF=<tag>` on a clean,
   committed worktree. Keep `build/` contents together.
2. Verify `make verify` and read the provenance file: `core_ref`,
   `core_commit` and `go_version` must match the target Nauthilus image.
3. Upload the four files into a new immutable PVC generation directory
   (never overwrite one referenced by running pods or rollback manifests) and
   pin it in the `subPath` mounts, following the same procedure as `rns_auth`.
4. Update `checksum` and `signer` in the module configuration together with the
   image and the Policy configuration from `examples/` (see the Draft section
   below), then roll out shadow before production.
5. Gates: all pods ready without restarts; signature verification and plugin
   start logged for `dkim2_intelligence`; catalog activation without schema or
   dependency errors; `composition_total{result="completed"}` increasing for
   DKIM2 traffic and no growth of `projection_invalid`.

## Rollback

Restore the previous image digest, runtime configuration, plugin checksums and
the immutable PVC generation pin together. Artifact, Policy schema and verifier
producer (Rspamd adapter and `dkim2d`) form one contract version; rolling back
only one of them makes every applicable request fail closed with
`projection_invalid`.

## Telemetry

`composition_total{result=...}` uses the bounded values `completed`,
`unavailable`, `projection_invalid`, `reputation_invalid`,
`correlation_invalid`, `geoip_invalid` and `composition_invalid`. A sustained
`projection_invalid` rate after a rollout indicates a producer/plugin contract
mismatch (for example a draft literal or binding mismatch).
