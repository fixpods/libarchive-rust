#!/bin/bash
sudo yum clean all
sudo yum install -y gcc  openssl-libs

sudo yum install -y make cmake
sudo yum install -y zlib-devel bzip2-devel lz4-devel openssl-devel libxml2-devel expat-devel
git clone https://github.com/BLAKE2/libb2.git
cd libb2/
./autogen.sh
./configure
make
sudo make install
git https://github.com/facebook/zstd.git
cd zstd/
./autogen.sh
./configure
make
sudo make install
cd ../

#git加速并安装rust工具链
git config --global url."https://github.91chi.fun/https://github.com/".insteadOf "https://github.com/"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustlang.sh
sh rustlang.sh -y

source ~/.bashrc


