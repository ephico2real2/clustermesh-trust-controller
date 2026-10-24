#!/bin/sh
# Compatibility entrypoint: qualify both shared-package datapath modules.
set -eu
exec sh /workspace/scripts/lab/qualify-datapath.sh
