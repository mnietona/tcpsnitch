# Maintainer: Gregory Van den Schrieck <gregory.vds@gmail.com>
# Contributor: Your Name <youremail@domain.com>

pkgname=tcpsnitch-git
pkgver=r152.a1b2c3d
pkgrel=1
pkgdesc="A network tracing tool using LD_PRELOAD and eBPF to investigate TCP/IP stack interactions."
arch=('x86_64' 'i686' 'aarch64')
url="https://github.com/GregoryVds/tcpsnitch"
license=('GPL3')

depends=('jansson' 'libpcap' 'libbpf' 'libelf')

makedepends=('git' 'clang' 'libbpf' 'bpftool' 'linux-headers' 'cmake')

# change main to BRANCH_NAME if the default branch is not main
source=("${pkgname}::git+${url}.git#branch=main")
md5sums=('SKIP')

pkgver() {
    cd "$srcdir/${pkgname}"
    printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)" 
}

prepare() {
    cd "$srcdir/${pkgname}"
    chmod +x configure
}

build() {
    cd "$srcdir/${pkgname}"
    ./configure
    make
}

package() {
    cd "$srcdir/${pkgname}"
    make DESTDIR="$pkgdir" install
}