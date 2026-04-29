#!/bin/bash
# None plugin — no public access. Engines treat empty stdout + exit 1 as
# "no NFT mint" or "mint without connection details" per their handler.
echo "no public-address in 'none' mode" >&2
exit 1
