# Homebrew package (macOS, Apple silicon)

`fluxvm.rb` installs the prebuilt package from a GitHub release: `fluxctl` and the signed `fluxvm-vz-runner` side by side in
`bin`, plus a `brew services` entry for the daemon. Nothing here is published yet: there is no tap until someone creates one.

## Cutting a release

1. Tag and push: `git tag v0.4.0 && git push origin v0.4.0`. The `Release (macOS package)` workflow builds the package on a hosted
   macOS runner, smoke-tests it, and attaches `fluxvm-0.4.0-macos-arm64.tar.gz` and its `.sha256` to the release for that tag
   (a **draft** release is created if there is none; publish it when you are happy).
2. Fill in the formula from the package (or from the `.sha256` file's hash):
   `scripts/update-homebrew-formula.sh 0.4.0 path/to/fluxvm-0.4.0-macos-arm64.tar.gz`
3. Put `fluxvm.rb` in a tap repository (`zyvorai/homebrew-fluxvm`, `Formula/fluxvm.rb`). Users then run
   `brew install zyvorai/fluxvm/fluxvm`.

## Build the package locally

`scripts/package-macos.sh` (add `--profile debug` for a quick, large, unoptimised build) writes
`target/package/fluxvm-<version>-macos-arm64.tar.gz`. It needs `guestkit` checked out next to this repository, like the macOS CI job.

## Notes

- The runner is deliberately not stripped or re-signed after packaging: its ad-hoc signature carries the
  `com.apple.security.virtualization` entitlement, and without it Virtualization.framework refuses to start a VM.
- `fluxctl` links Homebrew's `hivex`, hence `depends_on "hivex"`.
- The package is not notarised. Downloads through `brew` are not quarantined, so it runs; a tarball downloaded in a browser may need
  `xattr -d com.apple.quarantine`.
