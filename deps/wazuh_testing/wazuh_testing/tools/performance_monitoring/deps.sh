#!/bin/bash

yum install make gcc policycoreutils-python automake autoconf libtool epel-release git which sudo wget htop -y

yum groupinstall "Development Tools" -y

yum install python3 python3-devel -y

pip3 install ipython pandas psutil
