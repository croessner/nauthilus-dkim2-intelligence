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

## DKIM2 Draft-08 contract (plugin 0.3.0)

The plugin implements `draft-ietf-dkim-dkim2-spec-08` only. It must be rolled
out together with the Draft-08 Rspamd DKIM2 adapter and a Draft-08 `dkim2d`;
a Draft-07 or Draft-06 request (draft literal or bindings) is rejected with
`invalid_input` and no facts, which the core reports as `indeterminate` with
status `provider_unavailable`, exactly as described for Draft-07 below.

What changed on the wire:

- `resource.dkim2.draft` is `draft-ietf-dkim-dkim2-spec-08`. The projection
  binding frames the draft literal, so every Draft-07 binding value differs;
  the frame layout and the record fields are unchanged (21 hop fields).
- `resource.dkim2.verification_reason` and
  `resource.dkim2.authentication_reason` are closed vocabularies bound to
  their states (Draft-08 Section 14.1). New reasons: `custody_mismatch` and
  `body_history_unavailable` (FAIL), `invalid_recipe` (PERMERROR);
  `timestamp_invalid`, `envelope_mismatch`, `domain_alignment_mismatch`,
  `next_domain_mismatch`, `out_of_band_required` and `from_not_authentic`
  moved from PERMERROR to FAIL; `too_many_signatures` is gone. A projection
  exists only for verification PASS, whose only reason is `none`; a PASS
  projection carrying any other reason is now rejected. Authentication must
  repeat the verification result, except replay `replayed`
  (FAIL `duplicate_message_without_exploded`) and `indeterminate`
  (TEMPERROR `replay_indeterminate` or `replay_evidence_unavailable`).
- Hop `signature_algorithms` admits `mldsa44` (pure ML-DSA-44, Section 3.4).
  The Draft-07 composite `mldsa44-ed25519-sha512` is rejected.
- The optional `resource.dkim2.received_dsn_propagation` admits
  `forbidden_identity_misaligned` (29 characters, within the reference
  `max_length: 30`). The `/v1/dsn/sign` unsigned reasons
  (`delivery_status_identity_unavailable`, `delivery_status_from_not_authentic`)
  are a `dkim2d` REST header and never part of the projection.
- Per-set selectors and `|` groups in `s=` stay inside `dkim2d`; the
  projection carries neither.

The plugin output (`assessed_chain`, `smtp_peer`, `assessment_complete`) is
unchanged.

### Required production configuration changes

None for the Policy document: the reference
`examples/policy_dkim2_rspamd_verifier.yml` keeps its schemas, allowlist and
rules (every non-PASS verification or authentication result is still denied
by `deny_nonpass_verifier_state` or `deny_nonpass_authentication`). Update
`config.d/55-go-plugins.yml` (`checksum` of the new artifact) and roll out the
plugin, the Draft-08 Rspamd adapter and the Draft-08 `dkim2d` together; a
mixed Draft-07/Draft-08 deployment fails closed.

## DKIM2 Draft-07 contract (plugin 0.2.0)

The plugin implements `draft-ietf-dkim-dkim2-spec-07` only. It must be rolled
out together with the Draft-07 Rspamd DKIM2 adapter and a Draft-07 `dkim2d`;
any Draft-06 request (draft literal, removed facts, removed hop fields or
Draft-06 bindings) is rejected with `invalid_input` and no facts. The core
treats every error class of this required provider as a provider failure, so
the decision is `indeterminate` with status `provider_unavailable` (marked
retryable by the core); it is never permitted. `deny_incomplete_assessment`
only applies when the plugin completes with `assessment_complete: false`.

What changed on the wire:

- `resource.dkim2.draft` is `draft-ietf-dkim-dkim2-spec-07`.
- The facts `resource.dkim2.do_not_modify_state`,
  `resource.dkim2.do_not_explode_state` and
  `resource.dkim2.dns_testing_effective` are no longer sent and are rejected
  if present.
- `resource.dkim2.chain` records lose `do_not_modify` and `do_not_explode`
  (21 fields instead of 23); the hop/projection binding no longer frames those
  two flags, so every binding value differs from Draft-06.
- `resource.dkim2.replay_class` gains `not_eligible` (PASS where only the
  originator's `i=1` signature authenticated the message).
- `resource.dkim2.verification_reason` may carry the new `from_not_authentic`
  reason; it only occurs with non-PASS verification, which never reaches
  composition.
- Signature algorithms stay `rsa-sha256`, `rsa-sha512`, `ed25519-sha256`,
  `ed25519-sha512`.

What changed in the plugin output:

- `plugin.dkim2_intelligence.assessed_chain` loses `do_not_modify` and
  `do_not_explode` (32 fields instead of 34).
- `violation_classes` loses `do_not_modify_violated` and
  `do_not_explode_violated` (12 classes instead of 14, `max_items: 12`).
- `smtp_peer` (36 fields) and `assessment_complete` are unchanged.

### Required production configuration changes

The reference is `examples/policy_dkim2_rspamd_verifier.yml`. In the
`nauthilus-tests` Kubernetes source files:

`config.d/70-dkim2-policy.yml` (namespace `dkim2`):

1. `schema_contributions.static.accept-message-instance.versions.v1.facts`:
   delete the three fact entries `resource.dkim2.do_not_modify_state`,
   `resource.dkim2.do_not_explode_state` and
   `resource.dkim2.dns_testing_effective`. They are `required: true`, so a
   Draft-07 request is refused by admission while they remain. (mandatory)
2. Same list, `resource.dkim2.chain` `record_schema` (`id: verifier_chain`):
   delete the fields `do_not_modify` and `do_not_explode` and change
   `max_fields: 23` to `max_fields: 21`. (mandatory)
3. Same list, `plugin.dkim2_intelligence.assessed_chain` `record_schema`
   (`id: dkim2_intelligence_assessed_chain`): delete `do_not_modify` and
   `do_not_explode`, change `violation_classes` `max_items: 14` to
   `max_items: 12`, and `max_fields: 34` to `max_fields: 32`. (mandatory)
4. Rule `deny_integrity_violation`: remove `do_not_explode_violated` and
   `do_not_modify_violated` from `contains_any`. The production list also
   contains `terminal_oob_required`, which the plugin has never emitted; the
   reference Policy omits it (terminal next-domain custody is handled by
   `deny_terminal_nd`). (mandatory for the two retired classes; recommended
   for `terminal_oob_required`)
5. Rule `deny_replay`: add `not_eligible` to the `not_in` list
   (`first_seen`, `exploded`, `not_eligible`). Without it every originator-only
   message (single `i=1` signature) is denied as a replay. (operator decision;
   the reference Policy permits it)

`config.d/48-policy-api.yml` (Rspamd verifier client): remove
`dkim2.do_not_modify_state`, `dkim2.do_not_explode_state` and
`dkim2.dns_testing_effective` from `allowed_resource_attributes` so the
allowlist stays closed. (recommended)

`config.d/55-go-plugins.yml`, module `dkim2_intelligence`: set `checksum` to
the new artifact's SHA-256 and `signer` to `rns-auth-plugin-build-key-2026`
(see the move section above). `name`, `type`, `path`, `signature` and
`config` keys stay unchanged. The `reputation` module's `resource.dkim2.chain`
correlation fields (`sequence`, `message_instance`, `hop_binding`,
`signer_domain`) are unchanged.

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
