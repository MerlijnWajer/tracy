# Copyright 1999-2013 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=4

inherit eutils git-2

DESCRIPTION="Tracy, a system call tracer and injector."
HOMEPAGE="http://wizzup.org/tracy"
SRC_URI=""

EGIT_REPO_URI="git://github.com/MerlijnWajer/tracy.git"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~arm ~x86"
IUSE=""

DEPEND=""
RDEPEND="${DEPEND}"

src_unpack() {
	git-2_src_unpack
}

src_compile() {
	cd src && emake
}

src_install() {
	dolib.a src/libtracy.a
	dolib.so src/libtracy.so

	insinto /usr/include/tracy
	doins src/*.h
}

