#!/bin/bash
#
# SSH wrapper for connecting to BlockHost test VMs
# Uses the testing keypair from the repo
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SSH_KEY="${PROJECT_DIR}/testing/blockhost-test-key"

if [ ! -f "$SSH_KEY" ]; then
    echo "Error: Testing SSH key not found at $SSH_KEY"
    echo "Generate with: ssh-keygen -t ed25519 -f testing/blockhost-test-key -N ''"
    exit 1
fi

# Default to root user if not specified
HOST="${1:-}"
if [ -z "$HOST" ]; then
    echo "Usage: $0 <host-or-ip> [ssh-args...]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.122.145"
    echo "  $0 192.168.122.145 'cat /var/log/blockhost-install.log'"
    exit 1
fi

shift
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" "root@$HOST" "$@"
