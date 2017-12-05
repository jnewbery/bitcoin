#!/bin/sh

# F401: module imported but unused
flake8 --ignore=B,C,E,F,I,N,W --select=F401 .
