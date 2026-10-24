root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export SCAN="${SCAN:-$root/target/release/cacert-scan --roots $root/patterns/roots.pem --watch $root/patterns/watch.pem}"
# a plain mirror, not apt-cacher-ng: a full pass streams ~111 GiB and must not be cached
export MIRROR="${MIRROR:-http://deb.debian.org/debian}"
export SUITE="${SUITE:-trixie}"
export ARCH="${ARCH:-amd64}"
export COMPONENTS="${COMPONENTS:-main contrib non-free non-free-firmware}"
export SECURITY_MIRROR="${SECURITY_MIRROR:-http://security.debian.org/debian-security}"

# A suite's own index does not carry its security updates: ca-certificates in
# dists/trixie still ships the emSign and AAA roots that +deb13u1 removed, and
# browsers sit several releases behind. Index the overlays too and let the newest
# version win, so a scan describes an updated machine. Unstable has no overlays:
# its fixes go straight into the suite. Set OVERLAYS= to index the suite alone.
case $SUITE in
  unstable | sid | experimental | rc-buggy) : "${OVERLAYS=}" ;;
  *) : "${OVERLAYS=$SUITE-security $SUITE-updates}" ;;
esac
export OVERLAYS
