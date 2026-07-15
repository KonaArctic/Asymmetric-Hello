#!/bin/bash
set -o errexit
# Thanks https://codeberg.org/IPv6-Monostack/delegacy-rpz
#dig +tcp axfr @2a01:4f8:251:305f::1 rpz.delegacy.monostack.org > delegacy.zone
curl https://codeberg.org/IPv6-Monostack/delegacy-rpz/releases/download/v2026070201/rpz.delegacy.monostack.org.zone |
named-checkzone -o - rpz.delegacy.monostack.org. > delegacy.zone
