#!/bin/bash

aclocal && autoheader && automake && autoconf

./configure $@
