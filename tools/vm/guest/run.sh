#!/bin/sh
# Slice 18 acceptance, first boot (spec v2.2 §K S18 AC (d)): image this running
# system's disk live with tracked-freeze onto /dev/vdb, restore it onto
# /dev/vdc, and report everything over the serial ports. /dev/vda is the
# running system, /dev/vdb and /dev/vdc are blank disks of this VM. Progress
# goes to the console (ttyS0); the results go to the second port (ttyS1),
# where no kernel or systemd message can interleave with them.
#
# With `mode` = incremental on the seed (series B3), the writer keeps running
# after the full image, a live incremental image follows, and the chain is
# restored: the full plus the incremental.
set -u
SERIAL=/dev/ttyS0
RESULT=/dev/ttyS1
say() { echo "LR-STEP $*" > "$SERIAL"; }
now() { python3 -c 'import time; print(time.monotonic())'; }
SEED=/mnt/seed

say "installing"
install -m 0755 "$SEED/linuxreflect" /usr/local/sbin/linuxreflect
install -m 0755 "$SEED/lr-chain-check" /usr/local/sbin/lr-chain-check
install -m 0755 "$SEED/lr-restored-check" /usr/local/sbin/lr-restored-check
install -m 0644 "$SEED/lr-restored-check.service" /etc/systemd/system/lr-restored-check.service
# Enabled now, so it runs on the next boot: that is the restored copy's boot.
systemctl enable lr-restored-check.service > /dev/null 2>&1

mkfs.ext4 -q -F /dev/vdb && mkdir -p /mnt/dest && mount /dev/vdb /mnt/dest

say "writer"
mkdir -p /var/lib/lr-workload
python3 "$SEED/lr-writer" /var/lib/lr-workload > /run/lr-writer.timeline &
WRITER=$!
sleep 5

MODE=$(cat "$SEED/mode" 2> /dev/null || echo full)

say "backup"
now > /run/lr-backup.start
/usr/local/sbin/linuxreflect backup create --source /dev/vda --dest /mnt/dest --set system \
    --snapshot tracked-freeze --no-encrypt --compress none --json -v \
    > /run/lr-backup.json 2> /run/lr-backup.err
echo $? > /run/lr-backup.rc
now > /run/lr-backup.end
RESTORE_FROM=/run/lr-backup.json
if [ "$MODE" = incremental ] && [ "$(cat /run/lr-backup.rc)" = 0 ]; then
    # The system keeps changing between the members.
    sleep 20
    say "incremental"
    now > /run/lr-incremental.start
    /usr/local/sbin/linuxreflect backup create --source /dev/vda --dest /mnt/dest --set system \
        --type incremental --snapshot tracked-freeze --no-encrypt --compress none --json -v \
        > /run/lr-incremental.json 2> /run/lr-incremental.err
    echo $? > /run/lr-incremental.rc
    now > /run/lr-incremental.end
    RESTORE_FROM=/run/lr-incremental.json
fi
sleep 2
kill "$WRITER" 2> /dev/null
wait "$WRITER" 2> /dev/null

say "restore"
IMAGE=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["image_path"])' "$RESTORE_FROM" 2> /dev/null)
if [ -n "$IMAGE" ]; then
    /usr/local/sbin/linuxreflect restore prepare --image "$IMAGE" --target /dev/vdc --json \
        > /run/lr-prepare.json 2> /run/lr-prepare.err
    TOKEN=$(python3 -c 'import json; print(json.load(open("/run/lr-prepare.json"))["token"])' 2> /dev/null)
    /usr/local/sbin/linuxreflect restore apply --token "$TOKEN" --confirm --json \
        > /run/lr-apply.json 2> /run/lr-apply.err
    echo $? > /run/lr-apply.rc
    sync
fi

say "report"
{
    echo "LR-RESULT-BEGIN"
    tar -C /run -cf - lr-backup.start lr-backup.end lr-backup.rc lr-backup.json \
        lr-backup.err lr-incremental.start lr-incremental.end lr-incremental.rc \
        lr-incremental.json lr-incremental.err lr-prepare.json lr-prepare.err \
        lr-apply.json lr-apply.err lr-apply.rc lr-writer.timeline 2> /dev/null \
        | gzip | base64 -w 76
    echo "LR-RESULT-END"
} > "$RESULT"
sync
poweroff
