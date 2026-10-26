#!/bin/sh
# Run one development action for this plugin inside a clean Nauthilus core tree.
#
# Go plugins share packages with the host binary, so the plugin is only ever
# compiled as contrib/plugins/dkim2-intelligence of an exact CORE_REF checkout.
# The checkout is reset to the pristine ref before each run, so files from a
# previous sync or from the historical in-core plugin cannot leak into a run.
#
# Usage: in-nauthilus.sh test|vet|lint|fmt-check|sign
set -eu

action="${1:?usage: in-nauthilus.sh test|vet|lint|fmt-check|sign}"

: "${CORE_REPO:?CORE_REPO is required}"
: "${CORE_REF:?CORE_REF is required}"
: "${CORE_WORKDIR:?CORE_WORKDIR is required}"
: "${PLUGIN_DIR:?PLUGIN_DIR is required}"
GO="${GO:-go}"
GO_TAGS="${GO_TAGS:-netgo}"
GOLANGCI_LINT="${GOLANGCI_LINT:-golangci-lint}"
export GOEXPERIMENT="${GOEXPERIMENT:-runtimesecret}"

plugin_path="contrib/plugins/dkim2-intelligence"
plugin_pkgs="./${plugin_path}/..."
harness_pkg="server/policy/decision/service"
harness_tag="dkim2policyharness"

if [ "${INSTALL_PACKAGES:-0}" = "1" ]; then
	apk add --no-cache build-base git rsync >/dev/null
	git config --global --add safe.directory "${CORE_REPO}"
	git config --global --add safe.directory "${PLUGIN_DIR}"
fi

# prepare_core creates or resets the cached core checkout at the exact ref.
prepare_core() {
	if [ ! -d "${CORE_WORKDIR}/.git" ]; then
		mkdir -p "$(dirname "${CORE_WORKDIR}")"
		git clone --quiet --no-checkout --no-hardlinks "${CORE_REPO}" "${CORE_WORKDIR}"
	fi

	git -C "${CORE_WORKDIR}" fetch --quiet --tags --force "${CORE_REPO}" "+refs/tags/*:refs/tags/*" "+refs/heads/*:refs/remotes/origin/*"
	git -C "${CORE_WORKDIR}" checkout --quiet --force --detach "${CORE_REF}"
	git -C "${CORE_WORKDIR}" clean -qffdx
}

# sync_plugin replaces the core's plugin directory with this repository's sources.
sync_plugin() {
	rm -rf "${CORE_WORKDIR:?}/${plugin_path}"
	mkdir -p "${CORE_WORKDIR}/${plugin_path}"
	rsync -a \
		--exclude .git \
		--exclude build \
		--exclude go.mod \
		--exclude go.sum \
		"${PLUGIN_DIR}/" "${CORE_WORKDIR}/${plugin_path}/"
}

# install_policy_harness copies the build-tagged DKIM2 Policy scenario harness
# into the core decision service package, whose unexported runtime it drives.
# The files only compile with harness_tag, so a plain core build ignores them.
install_policy_harness() {
	cp "${PLUGIN_DIR}"/policytest/*_test.go "${CORE_WORKDIR}/${harness_pkg}/"
}

prepare_core

case "${action}" in
	sign)
		: "${ARTIFACT_PATH:?ARTIFACT_PATH is required}"
		: "${SIGNING_KEY:?SIGNING_KEY is required}"
		cd "${CORE_WORKDIR}"
		"${GO}" run -mod=vendor ./server/pluginloader/cmd/nauthilus-plugin-sign sign \
			--artifact "${ARTIFACT_PATH}" \
			--signature "${ARTIFACT_PATH}.minisig" \
			--private-key-file "${SIGNING_KEY}"
		exit 0
		;;
esac

sync_plugin
cd "${CORE_WORKDIR}"

echo "core ref ${CORE_REF} ($(git rev-parse HEAD)), $(${GO} version)"

case "${action}" in
	test)
		"${GO}" test -mod=vendor -tags="${GO_TAGS}" -race -count=1 ${plugin_pkgs}
		install_policy_harness
		"${GO}" test -mod=vendor -tags="${GO_TAGS},${harness_tag}" -race -count=1 \
			-run '^TestDKIM2CorrelatedPolicyScenarios$' ./${harness_pkg}
		;;
	vet)
		"${GO}" vet -mod=vendor -tags="${GO_TAGS}" ${plugin_pkgs}
		install_policy_harness
		"${GO}" vet -mod=vendor -tags="${GO_TAGS},${harness_tag}" ./${harness_pkg}
		;;
	lint)
		"${GOLANGCI_LINT}" run --build-tags="${GO_TAGS}" \
			--enable dupl --enable goconst --enable revive --enable govet --enable errcheck \
			--enable gocyclo --enable funlen --enable unused \
			${plugin_pkgs}
		;;
	fmt-check)
		unformatted="$(gofmt -l "${plugin_path}")"
		if [ -n "${unformatted}" ]; then
			echo "gofmt reports unformatted files:" >&2
			echo "${unformatted}" >&2
			exit 1
		fi
		;;
	*)
		echo "unknown action: ${action}" >&2
		exit 2
		;;
esac
