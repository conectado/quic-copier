#!/bin/bash

# Generator of useless data for testing

case $1 in
  "big")
    size="1G"
    ;;
  "medium")
    size="1M"
    ;;
  "small")
    size="1K"
    ;;
esac

head -c ${size} </dev/urandom >${1}_chungus
