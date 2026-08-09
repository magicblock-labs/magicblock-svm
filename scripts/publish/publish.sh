#!/usr/bin/env bash
# Publishes the workspace's forked solana-* crates to crates.io under
# the magicblock-* namespace, without renaming them in this repo (other
# crates still depend on them here by their solana-* name via path/git).
#
# How: `cargo metadata --no-deps` already resolves every `{ workspace =
# true }` field and merges workspace + per-crate `features` -- so
# instead of hand-parsing Cargo.toml, we ask cargo for the resolved
# answer and use jq to render a standalone Cargo.toml per crate:
# [package].name becomes magicblock-*, dev-dependencies are dropped
# (metadata tags each dependency's kind), and dependencies on the other
# three forked crates get `package = "magicblock-*"` added so they
# resolve against the newly published name instead of a sibling path.
#
# A crate's own `[lib]` name doesn't matter here: what a dependent
# writes in `use foo::...` comes from *its own* Cargo.toml key, not the
# producer's package/lib name (verified empirically) -- so
# `solana-svm = { package = "magicblock-svm" }` downstream keeps
# `use solana_svm::...` working unchanged.
#
# Standalone copies (not a rename in place) because this workspace's
# `[patch.crates-io]` intercepts the solana-* names for unrelated
# upstream crates -- renaming our local packages while that's active
# breaks the patch, and `cargo publish` for any workspace member
# resolves the *whole* workspace lockfile anyway, which would force
# every crate to already be published before the first one could be.
#
# Env vars:
#   CARGO_REGISTRY_TOKEN  crates.io token with publish rights (required unless DRY_RUN=true)
#   DRY_RUN               "true" to run `cargo publish --dry-run` and skip crates.io polling.
#                          Note: `--dry-run` still resolves dependencies against
#                          the *real* registry, so from a clean slate only the
#                          first crate (magicblock-account, which has no
#                          magicblock-* deps of its own) gets a full dry-run --
#                          the other three depend on siblings this run hasn't
#                          actually published, so the script falls back to
#                          `cargo metadata --no-deps` (manifest/feature
#                          validation, no registry lookup) for those instead.
set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
  echo "error: this script needs bash 4+. on macOS, try: brew install bash && /opt/homebrew/bin/bash $0 ..." >&2
  exit 1
fi

# --- config ---
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT/target/publish}"
DRY_RUN="${DRY_RUN:-false}"
REPOSITORY="https://github.com/magicblock-labs/magicblock-svm"

# old package name -> new published name, in publish order (deps before dependents)
RENAME_JSON='{"solana-account":"magicblock-account","solana-transaction-context":"magicblock-transaction-context","solana-program-runtime":"magicblock-program-runtime","solana-svm":"magicblock-svm"}'
declare -A CRATE_DIR=(
  [solana-account]=solana-account
  [solana-transaction-context]=transaction-context
  [solana-program-runtime]=program-runtime
  [solana-svm]=svm
)
ORDER=(solana-account solana-transaction-context solana-program-runtime solana-svm)

# Renders one crate's standalone Cargo.toml from `cargo metadata`
# output. $old/$rename/$versions/$repo are passed in via jq --arg(json).
# Non-dev dependencies (kind == null) are kept; a feature-forward token
# like "solana-bpf-loader-program/metrics" is dropped if that dependency
# was dev-only (not in $keep), since cargo hard-errors on a feature
# forwarding to a dependency the manifest no longer declares.
read -r -d '' RENDER_JQ <<'JQEOF' || true
def q: tojson;
def arr(a): "[" + ([a[] | q] | join(", ")) + "]";

.packages[] | select(.name == $old) as $pkg
| ($pkg.dependencies | map(select(.kind == null))) as $deps
| (reduce $deps[] as $d ({}; .[$d.name] = true)) as $keep
| ($pkg.features // {}) as $feats
| def feat_arr(a):
    "[" + ([a[] | select(
        (contains("/") | not)
        or (split("/")[0] as $dep | ($dep | startswith("dep:")) or ($keep[$dep] != null))
      ) | q] | join(", ")) + "]";
  def dep_line(d):
    (d.rename // d.name) + " = { " +
    ([ "version = " + (
         if ($rename[d.name] // null) != null then ($versions[$rename[d.name]] | q)
         else (d.req | q) end
       ) ]
     + (if (d.features|length) > 0 then ["features = " + arr(d.features)] else [] end)
     + (if d.optional then ["optional = true"] else [] end)
     + (if (d.uses_default_features|not) then ["default-features = false"] else [] end)
     + (if ($rename[d.name] // null) != null then ["package = " + ($rename[d.name] | q)] else [] end)
     | join(", ")) + " }";
  # Marks this export as its own workspace root. Without it, Cargo walks
  # up from $OUT_DIR (which defaults to a path inside this repo, under
  # target/) and finds the real workspace's Cargo.toml, then refuses to
  # treat this crate as an unlisted member of it.
  "[workspace]\n\n" +
  "[package]\n" +
  "name = " + ($rename[$old] // $old | q) + "\n" +
  (if $pkg.description then "description = " + ($pkg.description | q) + "\n" else "" end) +
  "version = " + ($pkg.version | q) + "\n" +
  "authors = " + arr($pkg.authors) + "\n" +
  "repository = " + ($repo | q) + "\n" +
  (if $pkg.homepage then "homepage = " + ($pkg.homepage | q) + "\n" else "" end) +
  "license = " + ($pkg.license | q) + "\n" +
  "edition = " + ($pkg.edition | q) + "\n" +
  "\n[features]\n" +
  ([$feats | to_entries[] | .key + " = " + feat_arr(.value)] | join("\n")) + "\n" +
  "\n[dependencies]\n" +
  ([$deps[] | select(.target == null) | dep_line(.)] | join("\n")) + "\n" +
  ( [$deps[] | .target] | unique | map(select(. != null))
    | map(. as $t | "\n[target." + ($t | tojson) + ".dependencies]\n" +
           ([$deps[] | select(.target == $t) | dep_line(.)] | join("\n")) )
    | join("\n") )
JQEOF

# --- resolve once, up front: the whole workspace's metadata, and the version each renamed crate will publish as ---
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
METADATA="$OUT_DIR/metadata.json"
cargo metadata --no-deps --format-version=1 --manifest-path "$ROOT/Cargo.toml" > "$METADATA"
VERSIONS="$(jq --argjson rename "$RENAME_JSON" '[.packages[] | select($rename[.name] != null) | {($rename[.name]): .version}] | add' "$METADATA")"

# --- export: one standalone Cargo.toml + copied src/ per crate, in dependency order ---
echo "Exporting standalone publish copies to $OUT_DIR"
: > "$OUT_DIR/manifest.txt"
for old in "${ORDER[@]}"; do
  new="$(jq -r --arg k "$old" '.[$k]' <<<"$RENAME_JSON")"
  dst="$OUT_DIR/$new"
  mkdir -p "$dst"
  cp -r "$ROOT/${CRATE_DIR[$old]}/src" "$dst/src"
  jq -r --arg old "$old" --argjson rename "$RENAME_JSON" --argjson versions "$VERSIONS" --arg repo "$REPOSITORY" \
    "$RENDER_JQ" "$METADATA" > "$dst/Cargo.toml"
  printf '%s\t%s\n' "$new" "$(jq -r --arg k "$new" '.[$k]' <<<"$VERSIONS")" >> "$OUT_DIR/manifest.txt"
  echo "  $old -> $dst"
done

# --- publish: each crate in order, waiting for one to be indexed before the next (which depends on it) resolves ---
wait_until_published() {
  local name="$1" version="$2" attempt
  for attempt in $(seq 1 40); do
    if cargo info "${name}@${version}" >/dev/null 2>&1; then
      echo "${name} ${version} is live on crates.io"
      return 0
    fi
    echo "waiting for ${name} ${version} to appear on crates.io (attempt ${attempt}/40)..."
    sleep 10
  done
  echo "timed out waiting for ${name} ${version} to appear on crates.io" >&2
  return 1
}

mapfile -t CRATE_LINES < "$OUT_DIR/manifest.txt"  # "name<TAB>version" per line, in publish order
for line in "${CRATE_LINES[@]}"; do
  name="${line%%$'\t'*}"
  version="${line#*$'\t'}"
  dir="$OUT_DIR/$name"

  echo "::group::publish ${name} ${version}"
  args=(--manifest-path "$dir/Cargo.toml" --no-verify --allow-dirty)
  [[ "$DRY_RUN" == "true" ]] && args+=(--dry-run)

  set +e
  output="$(cargo publish "${args[@]}" 2>&1)"
  status=$?
  set -e
  echo "$output"
  echo "::endgroup::"

  if [[ $status -ne 0 ]]; then
    # extract the missing package name, if `cargo publish` failed that way
    sibling="$(grep -oE 'no matching package named `[^`]+`' <<<"$output" | grep -oE '`[^`]+`' | tr -d '`')"
    if echo "$output" | grep -qi "already uploaded\|already exists"; then
      echo "${name} ${version} is already published, continuing"
    elif [[ "$DRY_RUN" == "true" && -n "$sibling" ]] && jq -e --arg n "$sibling" 'any(.[]; . == $n)' <<<"$RENAME_JSON" >/dev/null; then
      # Expected in a from-scratch dry run: cargo publish --dry-run still
      # resolves dependencies against the *real* registry, and $sibling is
      # one of our own crates this run hasn't actually published yet. Fall
      # back to a check that needs no registry lookup at all.
      echo "${sibling} isn't live on crates.io yet, so ${name} can't fully dry-run -- falling back to local manifest validation"
      cargo metadata --no-deps --format-version=1 --manifest-path "$dir/Cargo.toml" >/dev/null
      echo "${name}: manifest is structurally valid (features, dependency table, etc.)"
    else
      exit "$status"
    fi
  fi

  # no need to wait for the last crate -- nothing left depends on it
  is_last=false
  [[ "$line" == "${CRATE_LINES[-1]}" ]] && is_last=true
  if [[ "$DRY_RUN" != "true" && "$is_last" == "false" ]]; then
    wait_until_published "$name" "$version"
  fi
done
