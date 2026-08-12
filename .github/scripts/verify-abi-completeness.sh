#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# ABI-COMPLETENESS GATE: refuse to build a plugin artifact whose source implements Store methods
# that the PINNED busbar ABI cannot carry.
#
# WHY THIS EXISTS. `.busbar-ref` pins the exact busbar commit a release builds and packs against.
# The plugin's `impl Store for ...` is compiled against `busbar-api` from that commit, but the wire
# is `busbar-plugin-sdk`'s `dispatch` — the match arm that turns a decoded StoreRequest into a call
# on the store. `busbar_api::Store` gives every method a DEFAULT body, so a method the pinned SDK's
# dispatch never routes does not fail to compile: it compiles, ships, signs, attests, and then
# silently takes the default at runtime. busbar 74a1f9fa ("a task written through a plugin store is
# no longer discarded") is exactly that failure, already shipped once: a store that implemented
# `put_task` perfectly had every task DISCARDED at the ABI while `put_task` reported success.
#
# That class of defect is invisible to every other gate in this repo. The test suite runs against a
# busbar checkout too, but through the in-process trait, not the ABI; fmt/clippy/build cannot see it;
# verify-assets only proves an asset exists. So this script checks the one thing nothing else does:
#
#   for every method this repo implements in `impl Store for <T>`,
#   the pinned busbar's crates/plugin-sdk/src/lib.rs `dispatch` must actually call `store.<method>(`.
#
# A method implemented here but unrouted there is a SILENT DATA-LOSS PATH. It is a hard failure.
#
# This is deliberately generic — it is not a list of task methods. Any future Store method added to
# a plugin ahead of the pinned engine trips it the same way, so the gate cannot go stale the way a
# hardcoded pin can.
#
# Usage: verify-abi-completeness.sh <path-to-plugin-repo> <path-to-busbar-checkout>
set -euo pipefail

plugin_root="${1:?usage: verify-abi-completeness.sh <plugin-repo> <busbar-checkout>}"
busbar_root="${2:?usage: verify-abi-completeness.sh <plugin-repo> <busbar-checkout>}"

sdk="${busbar_root}/crates/plugin-sdk/src/lib.rs"
[ -f "$sdk" ] || { echo "::error::not a busbar checkout: ${sdk} does not exist" >&2; exit 1; }

# The single `impl Store for <T>` block in this repo's store crate. Found, not hardcoded, so the
# script is identical in all four store repos.
impl_file="$(grep -rl --include='*.rs' '^impl Store for ' "$plugin_root" \
  | grep -v '/target/' | head -1 || true)"
[ -n "$impl_file" ] || { echo "::error::no 'impl Store for' block found under ${plugin_root}" >&2; exit 1; }

# Slice the impl block: from `impl Store for` to the first column-0 `}`, then take the method names.
methods="$(awk '/^impl Store for /{inblock=1} inblock{print} inblock&&/^\}/{exit}' "$impl_file" \
  | sed -n 's/^    fn \([a-z0-9_]*\)(.*/\1/p' | sort -u)"
[ -n "$methods" ] || { echo "::error::parsed ZERO methods out of ${impl_file} — the parser is wrong, not the ABI" >&2; exit 1; }

echo "plugin store impl : ${impl_file}"
echo "pinned busbar sdk : ${sdk}"
echo "methods implemented here: $(echo "$methods" | wc -l | tr -d ' ')"
echo

missing=""
for m in $methods; do
  if grep -q "store\.${m}(" "$sdk"; then
    echo "  ok      ${m}"
  else
    echo "  MISSING ${m}"
    missing="${missing} ${m}"
  fi
done

if [ -n "$missing" ]; then
  echo
  echo "::error::ABI-COMPLETENESS FAILURE. The pinned busbar commit's plugin-sdk dispatch does not" \
       "route these Store methods that this plugin implements:${missing}." \
       "Packing a cdylib against this ABI would ship a plugin whose calls to those methods take" \
       "busbar_api::Store's DEFAULT bodies at runtime — succeeding silently while dropping the data." \
       "Do not release. Advance .busbar-ref to a busbar commit whose crates/plugin-sdk dispatch" \
       "carries these methods (and whose crates/api defines the row types they take)." >&2
  exit 1
fi

echo
echo "ABI-completeness OK: every Store method implemented here is routed by the pinned busbar's dispatch."
