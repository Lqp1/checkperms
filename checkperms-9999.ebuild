# Copyright 1999-2019 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

DESCRIPTION="Simple Live EBUILD for Checkperms script"
HOMEPAGE="https://github.com/lqp1/checkperms"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE=""

DEPEND=""
RDEPEND="${DEPEND}"
BDEPEND="dev-vcs/git"

SRC_URI=""
EGIT_REPO_URI="https://github.com/lqp1/${PN}.git"
EGIT_BRANCH="master"
EGIT_CHECKOUT_DIR="${S}"

PYTHON_COMPAT=( python{2_6,2_7,3_2,3_3} pypy2_0 )

inherit git-r3 distutils-r1 bash-completion-r1

python_install_all(){
	distutils-r1_python_install_all
	newbashcomp debian/checkperms-bin-completion.bash checkperms-bin-completion.bash
	doman debian/docs/*.1
}

