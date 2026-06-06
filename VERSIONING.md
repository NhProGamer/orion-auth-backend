# Versioning policy

This repo uses **SemVer 2.0.0** with a `v` prefix (Go-module convention).

```
vMAJOR.MINOR.PATCH        # stable release
vMAJOR.MINOR.PATCH-rc.N   # release candidate (only during a formal cut)
```

## When to bump what

The bump is decided by the *content* of the commit, using the conventional-commit
prefix as a signal.

| Commit prefix | Bump |
|---|---|
| `feat:` / `feat(scope):` | MINOR (`+1`, PATCH reset to 0) |
| `fix:`, `refactor:`, `docs:`, `test:`, `ci:`, `chore:`, `style:`, `revert:` | PATCH (`+1`) |
| Anything containing `BREAKING CHANGE:` or `feat!:` / `fix!:` | MAJOR (only after we reach `v1.0.0`) |

Pre-`v1.0.0` we never bump the major. The public API is not yet declared stable.

## When to cut a release candidate

`-rc.N` is reserved for **formal stabilisation cycles** — i.e. "we are preparing
`v0.42.0`, we cut `v0.42.0-rc.1`, run the smoke tests / staging deploys, and
either ship the final `v0.42.0` or cut `v0.42.0-rc.2`".

It is **not** a synonym for "I'm pushing a commit to staging". A push-by-push
prerelease cadence was the failure mode of the legacy `-pre*` / `-hf*` / `-b*`
tags (see [CHANGELOG.md](CHANGELOG.md) `v0.24.0` notes). The CI tag-format gate
in `.forgejo/workflows/test.yml` enforces the regex
`^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$` and rejects anything else.

## How to tag

Stable:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z

<one or two paragraphs of human notes>
See CHANGELOG.md for the full diff."

git push origin vX.Y.Z
fj release create vX.Y.Z --tag vX.Y.Z --body "$(awk '/^## \[vX.Y.Z\]/,/^## /' CHANGELOG.md | sed '$d')"
```

Release candidate:

```bash
git tag -a vX.Y.Z-rc.N -m "vX.Y.Z-rc.N — pre-release toward vX.Y.Z"
git push origin vX.Y.Z-rc.N
fj release create vX.Y.Z-rc.N --tag vX.Y.Z-rc.N --prerelease --body "Pre-release toward vX.Y.Z"
```

## When to bump MINOR vs MAJOR after v1.0.0

After `v1.0.0`:
- MINOR — new feature, backwards-compatible API addition.
- MAJOR — removed/renamed exported symbol, changed function signature, changed
  HTTP API contract in a way that breaks existing clients, schema migration that
  is not backwards-compatible.

A `feat!:` or a `BREAKING CHANGE:` footer in any commit between two stable tags
forces the next bump to MAJOR.

## How to read CHANGELOG.md

The CHANGELOG follows [Keep a Changelog](https://keepachangelog.com). The
`[Unreleased]` section accumulates entries between releases; when a stable is
cut, its contents move under the new `[vX.Y.Z]` heading.
