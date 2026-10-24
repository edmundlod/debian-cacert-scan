root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export SCAN="${SCAN:-$root/target/release/cacert-scan --roots $root/patterns/roots.pem --watch $root/patterns/watch.pem}"
# a plain mirror, not apt-cacher-ng: a full pass streams ~111 GiB and must not be cached
export MIRROR="${MIRROR:-http://deb.debian.org/debian}"
export SUITE="${SUITE:-trixie}"
export ARCH="${ARCH:-amd64}"
export COMPONENTS="${COMPONENTS:-main contrib non-free non-free-firmware}"
