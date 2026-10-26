# nauthilus-dkim2-intelligence

Correlated DKIM2 verifier, reputation and SMTP-peer intelligence for the
[Nauthilus](https://github.com/croessner/nauthilus) Policy layer, delivered as
an external native Go plugin.

- Repository: <https://github.com/croessner/nauthilus-dkim2-intelligence>
- Plugin module and config name: `dkim2_intelligence`
- Artifact: `dkim2-intelligence.so` (+ `.sha256`, `.minisig`, `.provenance`)
- Policy component: `dkim2/plugin.dkim2_intelligence.assessment`
- Supported DKIM2 protocol: `draft-ietf-dkim-dkim2-spec-07` with the
  `dkim2.verifier-projection.v1` projection (Draft-06 input is rejected)
- License: GPL-3.0-or-later (see [LICENSE](LICENSE)); the code is derived from
  Nauthilus, which is licensed under the GPL-3.0

## Purpose

A DKIM2 verifier (`dkim2d`, called by the Rspamd DKIM2 adapter) sends a sealed
verifier projection of the authenticated DKIM2 chain to the Nauthilus Policy
API (`dkim2/accept-message-instance`). This plugin is a fact-only provider: it
validates that projection, recomputes its SHA-256 bindings byte for byte,
correlates every signer hop with the preexisting Nauthilus reputation and the
current SMTP peer GeoIP/ASN evidence, applies explicit operator identity
contracts and publishes three facts (`assessed_chain`, `smtp_peer`,
`assessment_complete`) for Policy rules. It never parses messages, verifies
signatures, stores data, or decides permit/deny itself.

## Relationship to Nauthilus

- The plugin is an external native Go plugin. Go plugins must be built from
  exactly the same shared packages, toolchain, `GOEXPERIMENT` and build tags as
  the host, so it is compiled inside a clean clone of the exact Nauthilus
  release tree (`CORE_REF`), at `contrib/plugins/dkim2-intelligence/`.
- It uses the Nauthilus packages `pluginapi/v1`,
  `contrib/plugins/internal/reputationview` and
  `contrib/plugins/internal/telemetry` from that tree (tests also use
  `server/...` packages); there is no separate `go.mod`.
- Release artifacts are signed with minisign using the Nauthilus signing tool
  (`server/pluginloader/cmd/nauthilus-plugin-sign`) and delivered as an
  artifact set (optionally in a minimal carrier image) that Nauthilus loads with
  `verification_policy: signature_required`, a pinned SHA-256 checksum and a
  trusted signer.

### Compatibility rule

One artifact is valid for exactly one Nauthilus release (core commit, Go
toolchain, `GOEXPERIMENT=runtimesecret`, `netgo`). Rebuild, re-sign and re-pin
the checksum for every Nauthilus release, including patch releases; the
provenance file records the exact inputs. The Nauthilus loader refuses an
artifact built for another host identity.

| Plugin | DKIM2 draft | Built and tested against |
|--------|-------------|--------------------------|
| 0.2.0 | `draft-ietf-dkim-dkim2-spec-07` | Nauthilus `v4.0.2` (default `CORE_REF`) |
| 0.1.0 | `draft-ietf-dkim-dkim2-spec-06` | bundled in Nauthilus up to `v4.0.1` |

## Quick start

```sh
# Tests (go test -race), vet, golangci-lint and gofmt inside a v4.0.2 tree
make check CORE_REPO=/path/to/nauthilus CORE_REF=v4.0.2

# Release build with ABI check, checksum and minisign signature
make sign CORE_REPO=/path/to/nauthilus CORE_REF=v4.0.2 \
  SIGNING_KEY=/secure/minisign-key.b64
```

`make build` needs Docker; the builder image is
`golang:$(GO_VERSION)-alpine$(ALPINE_VERSION)` and must match the toolchain
of the selected Nauthilus release.

## Configuration

- [examples/go_plugin_dkim2_intelligence.yml](examples/go_plugin_dkim2_intelligence.yml):
  module composition fragment (GeoIP, reputation and `dkim2_intelligence`).
- [examples/policy_dkim2_rspamd_verifier.yml](examples/policy_dkim2_rspamd_verifier.yml):
  strict reference Policy for `dkim2/accept-message-instance`, including the
  executable fact and record schemas.
- [examples/policy_dkim2_observe.yml](examples/policy_dkim2_observe.yml):
  observation overlay for calibration.
- [examples/dkim2_rspamd_policy_request_v1.example.json](examples/dkim2_rspamd_policy_request_v1.example.json):
  a Draft-07 wire request with producer-coherent bindings.
- [docs/dkim2_rspamd_policy_contract.md](docs/dkim2_rspamd_policy_contract.md):
  the wire contract, including the Draft-07 binding encoding.
- [OPERATOR.md](OPERATOR.md): trust chain, the module entry for the external
  artifact, the exact production changes for Draft-07, rollout and rollback.
- [AGENTS.md](AGENTS.md): contribution rules.

## Repository layout

| Path | Content |
|------|---------|
| `*.go` | Plugin `main` package (composition, schema, configuration, telemetry). |
| `projection/` | Verifier projection decoding and binding recomputation (formerly `contrib/plugins/internal/dkim2projection`). |
| `testdata/record-contract.json` | Normative output record contract fixture. |
| `examples/` | Reference Policy, module fragment, observation overlay and wire request; the tests load them. |
| `policytest/` | Build-tagged (`dkim2policyharness`) end-to-end Policy scenarios; copied into the core decision service package to drive its compiled scheduler with the reference Policy. |
| `docs/` | Wire contract documentation. |
| `scripts/in-nauthilus.sh` | Runs test, vet, lint, fmt-check or sign inside a core checkout. |
| `scripts/build-in-nauthilus.sh` | Release builder executed inside the Go builder container. |
| `Dockerfile.artifact` | Minimal carrier image for a signed artifact set. |
| `LICENSE` | GPL-3.0 license text (copied from Nauthilus). |


## How the plugin is built

A Go plugin can only be loaded by a host that was built from exactly the same
shared packages, toolchain, `GOEXPERIMENT` and build tags. This repository
therefore has no `go.mod` of its own. Every compile, test, vet and lint run
happens inside a clean clone of the Nauthilus core at an exact `CORE_REF`,
with this repository copied to `contrib/plugins/dkim2-intelligence/`. Any
historical in-core copy of the plugin at that path is removed first. In the
core tree the projection package resolves as
`github.com/croessner/nauthilus/v4/contrib/plugins/dkim2-intelligence/projection`.

Core packages the plugin depends on (they resolve because compilation happens
inside the core tree):

- `pluginapi/v1` (plugin contract, decision values and records);
- `contrib/plugins/internal/reputationview` (shared reputation tuple encoding,
  also used by the core `reputation` plugin);
- `contrib/plugins/internal/telemetry` (bounded host metric helpers);
- tests additionally use `server/config`, `server/pluginregistry`,
  `server/pluginruntime`, `server/pluginloader` and `server/policy/...` to
  prove admission, catalog activation and the decision service end to end.

`contrib/plugins/internal/pluginutil` is not used. A core release that changes
or removes any of these packages requires a plugin update before `CORE_REF`
can move.

The release build (`make build`) mirrors the external `rns_auth` plugin:

1. Docker builder `golang:$(GO_VERSION)-alpine$(ALPINE_VERSION)`; the script
   fails when the builder toolchain differs from the `toolchain` line in the
   core `go.mod`.
2. Clean clone of `CORE_REPO` (mounted read-only) at `CORE_REF`.
3. `scripts/native_artifact_fingerprint` is computed over the pristine core
   tree before any plugin source is added.
4. Plugin sources (no tests, docs, examples or testdata) are copied into the
   core tree and compiled with `GOOS=linux GOARCH=amd64 CGO_ENABLED=1
   GOEXPERIMENT=runtimesecret go build -mod=vendor -tags=netgo
   -buildmode=plugin -trimpath` and the fingerprint ldflags plus
   `main.buildCommit`, `main.buildTime` and `main.buildTags`.
5. The core `server/pluginloader/testdata/nativebundle` checker verifies the
   declared host identity and loads the shared object to prove Go package ABI
   compatibility.
6. `build/dkim2-intelligence.so.provenance` records bundle commit and commit
   time, core commit and ref, Go version, experiment, tags and flags.

`make checksum` adds `dkim2-intelligence.so.sha256`. `make sign` signs with the
core `server/pluginloader/cmd/nauthilus-plugin-sign` tool and the minisign key
at `SIGNING_KEY` (default
`$(HOME)/.config/nauthilus/rns-auth-plugin-signing-key.b64`). The key is never
printed, copied into the build tree or committed.

## Make targets and variables

| Target | Effect |
|--------|--------|
| `make test` | `go test -race -count=1` for the plugin and `projection`, then the `policytest/` Policy scenarios against `examples/policy_dkim2_rspamd_verifier.yml`, inside the core checkout (local toolchain). |
| `make test-docker` | Same tests inside the exact release builder image. |
| `make vet` | `go vet` inside the core checkout. |
| `make lint` | `golangci-lint` with the core `.golangci.yml` and the core guardrail linters. |
| `make fmt-check` | Fails when `gofmt` would change a file. |
| `make check` | `fmt-check vet lint test`. |
| `make build` | Release build, ABI check and provenance (requires a clean worktree unless `ALLOW_DIRTY=1`). |
| `make checksum` | `build` plus SHA-256 file. |
| `make verify` | Re-checks the SHA-256 file of an existing artifact. |
| `make sign` | `checksum` plus detached minisign signature. |
| `make image` | Carrier image from an already signed artifact set. |
| `make clean` | Removes `build/` (including the cached core checkout). |

| Variable | Default | Meaning |
|----------|---------|---------|
| `CORE_REPO` | `$(HOME)/GoLandProjects/nauthilus` | Local core repository (read-only; mounted at `/core` for Docker targets). |
| `CORE_REF` | `v4.0.2` | Exact core tag or commit; rebuild for every Nauthilus release. |
| `GO_VERSION` | `1.27.3` | Builder image Go version; must equal the core `go.mod` toolchain. |
| `ALPINE_VERSION` | `3.24` | Builder image Alpine version. |
| `GOEXPERIMENT` | `runtimesecret` | Mandatory host experiment. |
| `GO_TAGS` | `netgo` | Host build tags. |
| `GO` | `go` | Local Go for `test`, `vet`, `lint`, `sign`. |
| `GOLANGCI_LINT` | `golangci-lint` | Linter binary. |
| `CORE_WORKDIR` | `build/core` | Cached core checkout, reset to `CORE_REF` and cleaned on every run. |
| `BUILD_DIR` | `build` | Output directory. |
| `ARTIFACT` | `dkim2-intelligence.so` | Artifact file name. |
| `BUNDLE_COMMIT` / `BUNDLE_BUILD_TIME` | `HEAD` and its commit time | Provenance; never the wall clock. |
| `SIGNING_KEY` | `$(HOME)/.config/nauthilus/rns-auth-plugin-signing-key.b64` | Minisign private key file. |
| `IMAGE` / `IMAGE_TAG` | `ghcr.io/croessner/nauthilus-dkim2-intelligence` / `$(CORE_REF)-<short sha>` | Carrier image name. |
| `ALLOW_DIRTY` | `0` | Set to `1` to build from a dirty worktree (provenance is then not release evidence). |

Example for the deployment target:

```sh
make check CORE_REF=v4.0.2
make sign CORE_REF=v4.0.2
```

## Plugin semantics

This native fact provider composes an admitted verifier projection with
preexisting generic reputation, current-peer GeoIP/ASN evidence and explicit
operator identity contracts. It has no Redis, HTTP, credential, effect, permit
or deny capability. DKIM2 remains responsible for parsing, cryptographic
verification, reconstruction, Recipe execution, replay handling and sealing.

The component is `dkim2/plugin.dkim2_intelligence.assessment`. Its only outputs
are `plugin.dkim2_intelligence.assessed_chain`, `.smtp_peer` and
`.assessment_complete`. The first collection contains the admitted ordered
chain (1–128 records, 32 declared fields, 262144 aggregate bytes); the second
contains one SMTP peer record (36 declared fields, 8192 aggregate bytes).
Conditional tuple fields are absent when their state does not permit details.
The independent normative fixture is `testdata/record-contract.json`; the
executable field schema is in
`examples/policy_dkim2_rspamd_verifier.yml`.

### Input authority and correlation

The generic host must bind the exact configured reputation and geographic
components, declare their output schemas and schedule both before this
component. Reputation additionally depends on GeoIP for the optional typed ASN
extractor. A missing dependency, wrong producer, hidden consumed record field
or incompatible type prevents catalog activation. Names in the Policy
`providers` map are authored aliases; native `component` selects the exact
registered component, so two modules may both export `assessment` without
sharing authority. Omitting `component` preserves the map-name default.

Projection validation and binding recomputation have one implementation in
the `projection` subpackage. This checks the already supplied semantic projection;
it does not reconstruct or verify DKIM2 messages. Every signer assessment must
match the corresponding canonical domain, sequence, Message-Instance and
32-byte hop binding, in the same order. The current target must be the final
admitted hop. Missing, duplicated, reordered, oversized or forged correlations
return `invalid_input` with no facts. The provider first builds and validates
both collections, then publishes all three facts atomically.

All reputation tuples retain the exact configured profile, state, band,
override and, when permitted, all six measurement fields. The pure
`internal/reputationview` package owns tuple encoding and validation for both
producer and composer. IP, network and ASN remain separate tuples. A missing
ASN produces an unavailable ASN tuple without inventing a subject or querying
an empty identity. A fresh geographic result cannot conceal an unavailable
reputation lookup. `assessment_complete=true` means structurally complete
correlation, including explicit unavailable states; it is not a trust or
permission result.

### Configuration semantics

Merge the module composition fragment by module and target-binding identity
with the generic reputation configuration. The canonical verifier Policy owns
the provider schedule and all fact schemas in one place. Preserve the reputation model, primary Redis,
opaque-key and source admission settings. Different target namespaces need
different reputation component names. The supplied DKIM2 component is
`assessment`; an authentication component must have another local name when
both are enabled in the same module.

The configuration requires `reputation_provider`, `reputation_fact`,
`geoip_provider` and `decision_profile` (`fast`, `operational` or `baseline`).
These values define the registered input contract and require restart when
changed; a SIGHUP reload that changes them is rejected as restart-bound.
`identity_contracts` and `signer_sets` reload on SIGHUP together as one
immutable snapshot. Unknown configuration keys fail registration.

An identity contract names explicit canonical domains, optional canonical
CIDRs and optional integer ASNs. CIDR match has priority when both kinds are
configured; ASN match retains the weaker, separate `asn` strength. No ISP,
mailbox provider or forwarding service is automatically trusted. Historical
membership in an explicit contract or its referenced signer set yields only `domain_only`.
Only the current target can acquire `matched/cidr` or `matched/asn` from the
actual SMTP peer. Missing domains, mismatches and unavailable required ASN
evidence remain distinct. With no configured contracts there is no inferred
provider allowlist.

GeoIP evidence must describe exactly the current canonical SMTP IP. Fresh or
stale evidence carries a bounded age; unavailable/not-found evidence cannot
carry fabricated location or ASN details. Geographic freshness is determined
by the generic GeoIP provider's opened database snapshot and configured age
limits. The composer does not refresh databases or perform network lookups.

### Privacy and validation

The output excludes raw IP duplication, subject tags, message headers or
values, bodies, keys, selectors, signatures, Recipe payloads and recipe
digests. Hop bindings and ASN organization are provider-private in the
executable schema. The lower-case verifier signature state is copied
unchanged. Closed violation classes describe observed semantic conditions;
Recipe authorization and final action belong to Policy rules.

Run the package tests with `make test` (see above). The configured-generation test uses the
actual composer and explicitly identified upstream test doubles to prove
schema, dependency and visibility activation. It does not claim a Redis read,
MMDB lookup or native artifact load. Those boundaries have separate generic
provider integration and native-bundle checks. `make build` proves the actual
native load contract against the exact `CORE_REF` host with the core's
`server/pluginloader/testdata/nativebundle` checker.

### Operational telemetry

The host-scoped `composition_total` counter has one additional `result` label:
`completed`, `unavailable`, `projection_invalid`, `reputation_invalid`,
`correlation_invalid`, `geoip_invalid`, or `composition_invalid`. It follows
the actual enrichment callback and never labels signers, peer addresses, hop
identities, Recipe data or caller input. `completed` means composition passed
its contract checks; the selected Policy still owns the delivery decision.
Exporter failure does not change composition results.

## History

- Up to Nauthilus `v4.0.1` the plugin lived in the Nauthilus core repository as
  `contrib/plugins/dkim2-intelligence` (with the private helper package
  `contrib/plugins/internal/dkim2projection`) and was built, signed and shipped
  inside the Nauthilus image, implementing DKIM2 Draft-06.
- Starting with Nauthilus `v4.0.2` it is maintained here as an external plugin.
  The first commit imports the unmodified `v4.0.1` sources; the projection
  package became the `projection` subpackage.
- Plugin `0.2.0` ports the contract to `draft-ietf-dkim-dkim2-spec-07`
  (see [OPERATOR.md](OPERATOR.md) for the exact contract changes).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). Copyright (C) 2026 Christian Roessner.
