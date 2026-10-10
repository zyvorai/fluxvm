# Homebrew formula for the prebuilt macOS package (see scripts/package-macos.sh and .github/workflows/release-macos.yml).
# The version and sha256 below are filled in by scripts/update-homebrew-formula.sh when a release is published.
class Fluxvm < Formula
  desc "VM control plane: Linux VMs on Apple silicon with Virtualization.framework"
  homepage "https://github.com/zyvorai/zyvor-fluxvm"
  version "0.4.0"
  url "https://github.com/zyvorai/zyvor-fluxvm/releases/download/v#{version}/fluxvm-#{version}-macos-arm64.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"

  depends_on arch: :arm64
  depends_on macos: :sonoma
  depends_on "hivex"

  def install
    # The runner must sit next to fluxctl: that is where the daemon looks for it first.
    bin.install "bin/fluxctl", "bin/fluxvm-vz-runner", "bin/fluxvm-vz-switch"
    pkgshare.install "config.example.toml"
  end

  service do
    run [opt_bin/"fluxctl", "serve"]
    keep_alive true
    log_path var/"log/fluxvm.log"
    error_log_path var/"log/fluxvm.log"
  end

  def caveats
    <<~EOS
      Try it:
        fluxctl run                  # a throwaway Debian VM and a shell
      Run the daemon in the background:
        brew services start fluxvm   # API on 127.0.0.1:7788
      Restoring VM snapshots needs an unlocked login session.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/fluxctl --version")
    assert_predicate bin/"fluxvm-vz-runner", :executable?
    assert_predicate bin/"fluxvm-vz-switch", :executable?
    assert_match "com.apple.security.virtualization",
                 shell_output("codesign -d --entitlements - #{bin}/fluxvm-vz-runner 2>&1")
  end
end
