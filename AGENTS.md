# Repository rules

This repository hosts the external Nauthilus native Go plugin
`dkim2-intelligence` (module `dkim2_intelligence`, artifact
`dkim2-intelligence.so`). These rules are mandatory for every change.

## Language and style

- Write code, comments, commit messages and documentation in English.
- Every hand-written named function and method, including unexported ones and
  tests, has a concise English doc comment that explains intent, invariants or
  security assumptions.
- Keep names free of planning labels, task IDs or milestone numbers.

## Build and test model

- Never add a `go.mod` here. The plugin compiles only inside a clean Nauthilus
  core checkout at an exact `CORE_REF`; use the Makefile targets
  (`make test`, `make vet`, `make lint`, `make fmt-check`, `make check`,
  `make build`). Do not invent ad hoc build commands.
- `GOEXPERIMENT=runtimesecret`, `-tags=netgo`, `-mod=vendor` and the core
  release toolchain are part of the plugin ABI. Do not change them without a
  matching core change.
- `make check` must pass before every commit. `make build` (with its ABI check
  against `CORE_REF`) must pass before a release or a `CORE_REF` change.
- Never sign or publish without an explicit maintainer request. Never print,
  copy or commit signing keys or other secrets.
- Do not modify the core repository; it is an input mounted read-only.

## Engineering rules

- Tests first: write a focused reproducer or contract test before fixing a
  bug or changing protocol behavior, and keep it as regression coverage.
- Fail closed: ambiguous, unknown, out-of-vocabulary, incoherent or
  older-draft input is rejected with `invalid_input` and no partial facts.
  Never weaken validation, bindings or tests to make input pass.
- The DKIM2 draft literal and the projection binding encoding are part of the
  contract. Bindings must match the `dkim2d` producer byte for byte; prove each
  change with a real producer fixture.
- Fix root causes. Change a test only when the test itself is wrong.
- Keep projection validation in `projection/` and composition in the `main`
  package; shared core helpers stay in the core (`reputationview`,
  `telemetry`, `pluginapi/v1`).
- Never log or emit raw recipients, message content, keys or signatures.
  Metric labels stay on the bounded `result` vocabulary.
- Keep `examples/`, `testdata/record-contract.json` and `schema.go` in sync;
  the tests enforce this.

## Commits

Use `Prefix: Concise headline` with a short bullet-list body, and end the
message with the trailer line
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

Allowed prefixes: `Add`, `Change`, `Fix`, `Remove`, `Refactor`, `Test`,
`Docs`, `Build`, `Ci`, `Vendor`, `Security`, `Chore`. Split unrelated work
into separate commits.
