#!/bin/sh
# BlockHost pre-install disclaimer
#
# Called from preseed/blockhost.preseed via `d-i preseed/early_command`.
# Runs before any partitioning — prompts for a confirmation phrase.
# Exit 0 = proceed. Non-zero = preseed aborts and host powers off.

# Take over tty1 so read/echo are interactive
if [ -e /dev/tty1 ]; then
    exec </dev/tty1 >/dev/tty1 2>&1
fi

PHRASE="Yes I understand"

show_disclaimer() {
    # clear may not be available in the installer environment
    printf '\033[2J\033[H' 2>/dev/null || true
    cat <<'EOF'

  ===============================================================

                   !!  WARNING -- READ CAREFULLY  !!

  Continuing will WIPE the connected hard drive and install
  BlockHost.

  All existing data on the target disk will be lost permanently.

  To continue, type the following phrase exactly (case-sensitive):

                         Yes I understand

  To cancel and power off, press Ctrl+C.

  ===============================================================

EOF
}

# Bail out on Ctrl+C with a non-zero exit so the outer `|| poweroff`
# in preseed kicks in
trap 'echo; echo "Cancelled."; exit 1' INT TERM

for attempt in 1 2; do
    show_disclaimer
    printf '> '
    # -r so backslashes aren't interpreted; IFS= so whitespace is preserved
    IFS= read -r INPUT || exit 1
    if [ "$INPUT" = "$PHRASE" ]; then
        printf '\033[2J\033[H' 2>/dev/null || true
        echo "Confirmed. Starting installation..."
        sleep 1
        exit 0
    fi
    if [ "$attempt" -lt 2 ]; then
        echo
        echo "Phrase does not match. One more attempt."
        sleep 2
    fi
done

echo
echo "Confirmation failed. Powering off in 3 seconds."
sleep 3
exit 1
