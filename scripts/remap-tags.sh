#!/usr/bin/env bash
#
# remap-tags.sh — Remap 63 chaotic historical tags onto a SemVer-by-content
# scheme. See the approved plan at .claude/plans/utilise-context7… or the
# CHANGELOG for the why.
#
# The mapping is hard-coded below for auditability — every (old, sha, new)
# triple is intentional, derived from the commit subject's conventional-commit
# type at the time of remap design. Re-running is idempotent: existing local
# tags are skipped, missing Forgejo releases are ignored.
#
# Usage:
#   scripts/remap-tags.sh dry-run     # print the operations, do nothing
#   scripts/remap-tags.sh execute     # apply
#
# Requires: git, fj (Forgejo CLI), authenticated to git.nhsoul.fr.

set -euo pipefail

REMOTE="${REMOTE:-origin}"

# Mapping rows: "old_tag|sha|new_tag"
# Order matters: chronological, so partial progress remains coherent.
MAPPING=(
  "0.1.0|1c7e629|v0.1.0"
  "0.1.0-hf1|22298e2|v0.1.1"
  "0.1.0-hf2|24d0405|v0.2.0"
  "0.1.0-hf3|db0ecf6|v0.3.0"
  "0.1.0-hf4|293ffe0|v0.3.1"
  "0.1.0-hf5|1486e3e|v0.4.0"
  "0.2.0|1dc7ae7|v0.5.0"
  "0.2.0-hf1|d482bd7|v0.5.1"
  "0.2.0-hf2|543ab25|v0.5.2"
  "0.2.1|bdbe9b0|v0.5.3"
  "0.2.1-hf1|526cb55|v0.5.4"
  "0.2.1-hf2|3ac2c5d|v0.6.0"
  "0.2.2|0e2c177|v0.6.1"
  "0.2.2-hf1|5b940d7|v0.6.2"
  "0.2.2-hf2|42ef552|v0.6.3"
  "0.2.2-hf3|9ab5e96|v0.6.4"
  "0.2.2-hf4|a2a78df|v0.7.0"
  "0.2.3-pre1|6970287|v0.8.0"
  "0.2.4-pre1|b6e3722|v0.8.1"
  "0.2.4-pre2|7ddccf6|v0.9.0"
  "0.2.5-pre1|1cdd145|v0.9.1"
  "0.2.5-pre2|fbfb642|v0.9.2"
  "0.2.5-pre3|683138f|v0.9.3"
  "0.2.5-pre4|d1bbc8f|v0.10.0"
  "0.2.5-pre5|2b9b50f|v0.11.0"
  "0.2.5-pre6|b1fd3ff|v0.12.0"
  "0.2.5-pre7|3b643ba|v0.12.1"
  "0.2.5-pre8|068806a|v0.13.0"
  "0.2.5-pre9|3d846b1|v0.14.0"
  "0.2.5-pre10|52de728|v0.15.0"
  "0.2.5-pre11|2e20bd3|v0.16.0"
  "0.2.6-pre1|0280d03|v0.16.1"
  "0.2.6-pre2|ed85226|v0.16.2"
  "0.2.6-pre3|0fc2d23|v0.16.3"
  "0.2.6-pre4|e2f3911|v0.16.4"
  "0.2.6-pre5|a2cb61b|v0.16.5"
  "0.2.6-pre6|428170b|v0.16.6"
  "0.2.6-pre7|4d3bb1f|v0.16.7"
  "0.2.6-pre8|fb504fe|v0.16.8"
  "0.2.6-pre9|484c01c|v0.16.9"
  "0.2.6-pre10|e938bfb|v0.16.10"
  "0.2.6-pre11|3602a1d|v0.16.11"
  "0.2.6-pre12|92b7806|v0.16.12"
  "0.2.6-pre13|ff82d57|v0.16.13"
  "0.2.6-pre14|1b6444b|v0.16.14"
  "0.2.6-pre15|7853e29|v0.16.15"
  "0.2.6-pre16|e3d751a|v0.17.0"
  "0.2.6-pre17|9814d87|v0.17.1"
  "0.2.6-pre18|bd19be1|v0.17.2"
  "0.2.6-pre19|0cbb500|v0.18.0"
  "0.2.7-pre1|d5aad34|v0.19.0"
  "0.2.7-pre2|720d240|v0.19.1"
  "0.2.7-pre3|c02879c|v0.19.2"
  "0.2.7-pre4|588781d|v0.20.0"
  "0.2.7-pr5|2c52f66|v0.21.0"
  "0.2.7-pre6|e633b9b|v0.21.1"
  "0.2.7-pre7|3d4aec8|v0.21.2"
  "0.2.7-pre8|1f19f4e|v0.21.3"
  "0.2.7-pre9|98ec5ab|v0.22.0"
  "0.2.7-pre10|99640eb|v0.23.0"
  "0.2.7-pre11|08518db|v0.23.1"
  "0.2.8-b1|1bd722d|v0.23.2"
  "0.2.8-b2|f924901|v0.23.3"
)

mode="${1:-}"
case "$mode" in
  dry-run|execute) ;;
  *)
    echo "usage: $0 dry-run|execute" >&2
    exit 64
    ;;
esac

# Pretty step prefix.
say() { printf '\033[1;34m[%s]\033[0m %s\n' "$1" "$2"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$1"; }

run() {
  if [[ "$mode" == "dry-run" ]]; then
    printf '  + %s\n' "$*"
  else
    "$@"
  fi
}

# Idempotent: returns 0 if local tag already exists at the desired sha.
local_tag_at_sha() {
  local tag="$1" want_sha="$2"
  local have_sha
  have_sha="$(git rev-parse "refs/tags/$tag" 2>/dev/null || true)"
  [[ -n "$have_sha" && "$have_sha" == "$want_sha"* ]]
}

remap_one() {
  local old="$1" sha="$2" new="$3"
  say "$old → $new" "sha=$sha"

  # 1. Create new local tag at the same commit (idempotent).
  if local_tag_at_sha "$new" "$sha"; then
    say "skip" "local tag $new already at $sha"
  else
    run git tag "$new" "$sha"
  fi

  # 2. Push the new tag to the remote.
  run git push "$REMOTE" "$new" 2>&1 | grep -v 'Everything up-to-date' || true

  # 3. Delete the Forgejo release tied to the old tag (if any).
  if [[ "$mode" == "execute" ]]; then
    fj release delete "$old" 2>/dev/null && say "release deleted" "$old" \
      || warn "no release for $old (ok)"
  else
    printf '  + fj release delete %s (best-effort)\n' "$old"
  fi

  # 4. Delete the old remote tag.
  if [[ "$mode" == "execute" ]]; then
    fj tag delete "$old" 2>/dev/null && say "tag deleted" "$old" \
      || warn "remote tag $old already absent"
  else
    printf '  + fj tag delete %s\n' "$old"
  fi

  # 5. Delete the old local tag.
  if git rev-parse "refs/tags/$old" >/dev/null 2>&1; then
    run git tag -d "$old"
  fi

  # 6. Create the Forgejo release on the new tag.
  local body
  body="$(printf 'Remap from %s.\n\nCommit: %s' "$old" "$sha")"
  if [[ "$mode" == "execute" ]]; then
    if fj release view "$new" >/dev/null 2>&1; then
      say "skip" "release $new already exists"
    else
      fj release create "$new" --tag "$new" --body "$body" \
        || warn "failed to create release $new (manual recovery)"
    fi
  else
    printf '  + fj release create %s --tag %s --body "Remap from %s"\n' "$new" "$new" "$old"
  fi
}

say "remap" "mode=$mode rows=${#MAPPING[@]}"
for row in "${MAPPING[@]}"; do
  IFS='|' read -r old sha new <<<"$row"
  remap_one "$old" "$sha" "$new"
done
say "done" "processed ${#MAPPING[@]} rows"
