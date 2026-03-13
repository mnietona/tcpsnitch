# Maintainer: Your Name <youremail@domain.com>
pkgname=tcpsnitch-git
pkgver=0
pkgrel=1
pkgdesc="A tracing tool designed to investigate the interactions between an application, the TCP/IP stack and the network."
arch=('i686' 'x86_64')
url="https://github.com/GregoryVds/tcpsnitch"
license=('unknown')
depends=('jansson' 'libpcap' 'libbpf')
makedepends=('git' 'clang' 'libbpf' 'bpftool' 'linux-headers')
source=('tcpsnitch-git::git+https://github.com/GregoryVds/tcpsnitch.git') # mettre la branch
md5sums=('SKIP')

pkgver() {
    cd "$srcdir/${pkgname%-git}"
    printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)" 
}

build() {
    cd "$srcdir/${pkgname%-git}"
    ./configure
    make
}

package() {
    cd "$srcdir/${pkgname%-git}"
    make DESTDIR="$pkgdir/" install
}