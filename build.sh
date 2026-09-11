#!/usr/bin/env bash
# Copyright MMQR Development
# Build the DOCSIS provisioning monitor with the build time compiled in.
#
# The same five steps as docsis_admin_web_app/build.sh, in the same order and
# for the same reasons. There is no pre-compression step here: nothing in this
# project embeds a static asset tree.
#
# --deploy is opt-in because the checks below are something you run constantly
# during development and pushing a binary to the distribution server is not. An
# unrecognised argument is a HARD ERROR, because the expensive failure is
# typing --deply, watching a clean build scroll past, and believing the server
# got it.
set -euo pipefail

cd "$(dirname "$0")"

# The one binary this project installs.
BINARIES=(docsis_monitor)

# Statically linked against musl, and everything below -- including the tests --
# runs on this target so that what is checked is what ships.
#
# The distribution server refuses a dynamically linked binary with HTTP 422,
# which is reasonable of it: these land on hosts whose libc nobody has checked.
#
# musl rather than glibc's -C target-feature=+crt-static. That links, and then
# SEGFAULTS in getpwnam; drop_privileges calls it before it even checks whether
# it is root, so every service would die on start. musl reads /etc/passwd
# directly and answers correctly. Measured both ways with the same probe.
TARGET=x86_64-unknown-linux-musl

DEPLOY=0

for arg in "$@"; do
	case "$arg" in
	--deploy) DEPLOY=1 ;;
	*)
		echo "unknown argument: $arg" >&2
		echo "usage: ./build.sh [--deploy]" >&2
		exit 2
		;;
	esac
done

# rustup puts cargo here and a login shell adds it; a script run from cron or
# from an editor gets neither. Say so rather than failing with "command not
# found" three lines later.
if ! command -v cargo >/dev/null 2>&1; then
	if [ -x "$HOME/.cargo/bin/cargo" ]; then
		PATH="$HOME/.cargo/bin:$PATH"
		export PATH
	else
		echo "cargo is not on PATH and $HOME/.cargo/bin/cargo does not exist" >&2
		exit 1
	fi
fi

# The musl target needs both halves: rustc's std for it, and a C compiler for
# the crates that build C. Named separately because they are installed
# separately and only one of them is rustup's business.
if ! rustc --print target-list | grep -qx "$TARGET"; then
	echo "rustc does not know $TARGET" >&2
	exit 1
fi
if ! rustup target list --installed | grep -qx "$TARGET"; then
	echo "the $TARGET std is not installed: rustup target add $TARGET" >&2
	exit 1
fi
if ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
	echo "x86_64-linux-musl-gcc is not on PATH; install the musl toolchain" >&2
	exit 1
fi

# 1. Formatting. Unlike gofmt, cargo fmt --check exits non-zero and prints the
#    diff, so its status is the check.
echo "== cargo fmt"
cargo fmt --check

# 2. Lints, at the level this project's own gate uses: a warning that is
#    allowed to accumulate is a warning nobody reads.
echo "== cargo clippy"
cargo clippy --all-targets --target "$TARGET" -- -D warnings

# 3. The default test set, as musl binaries. It needs nothing but the source tree.
echo "== cargo test"
cargo test --target "$TARGET"

# 4. The build time is pinned into the binary rather than left to the
#    executable's mtime.
#
#    --version falls back to that mtime, which is right for a working copy and
#    wrong the moment a binary is copied anywhere: cp without -p rewrites it,
#    and an unpacked archive carries whatever the archive said. A release is
#    exactly the case where the binary travels, so the stamp is fixed here.
echo "== cargo build"
STAMP="$(date +%s)"
DOCSIS_BUILD_TIME="$STAMP" cargo build --release --target "$TARGET"

# 5. Read the version back OUT of each binary -- not an echo of the variable --
#    and require it to be the stamp we just pinned.
#
#    That catches the failure this step exists for: a cached artefact that was
#    not rebuilt still answers, and answers with the stamp from whenever it was
#    last linked. Printing the value we set would agree with itself and prove
#    nothing.
echo "== version"
for b in "${BINARIES[@]}"; do
	out="$("target/$TARGET/release/$b" --version)"
	printf '  %-24s %s\n' "$b" "$out"
	if [ "${out%% *}" != "$STAMP" ]; then
		echo "$b reports ${out%% *}, not the $STAMP this build pinned;" >&2
		echo "it was not rebuilt, so it is not the binary you think it is" >&2
		exit 1
	fi
done

if [ "$DEPLOY" = 1 ]; then
	echo "== deploy"
	if ! command -v distback-send.pl >/dev/null 2>&1; then
		echo "distback-send.pl is not on PATH" >&2
		exit 1
	fi
	# One call per binary: distback keys on the program name and the build
	# epoch it reads back out of --version, so each has to go up separately.
	for b in "${BINARIES[@]}"; do
		distback-send.pl --program "target/$TARGET/release/$b"
	done
fi
