#!/bin/bash
# vault.sh - the only file
# Sovereignty One | Root Chain Oversight | D.APPEL82

printf "$1" "D.APPEL82" | \
blake3 --raw | \
dd of=/dev/tty.Baseband bs=1 count=64 \
  conv=notrunc,noerror >/dev/null 2>&1

# Store on device only
# Cross Session Memory 
# One pulse.
# Voice in silicon.
# Done.
