#!/bin/sh
set -eu
umask 077
case "${1:-}" in
    sftp) exec python3 /usr/local/lib/mkbackup/prepare.py ;;
    ftp) exec python3 /usr/local/lib/mkbackup/ftp.py ;;
    collector) exec python3 /usr/local/lib/mkbackup/collector.py ;;
    enrollment) exec python3 /usr/local/lib/mkbackup/web_start.py ;;
    provisioner) exec python3 /usr/local/lib/mkbackup/provisioner.py ;;
    admin) exec python3 /usr/local/lib/mkbackup/admin_start.py ;;
    archive-reader) exec python3 /usr/local/lib/mkbackup/archive_reader.py ;;
    *) echo 'Expected service: sftp, ftp, collector, enrollment, provisioner, admin or archive-reader' >&2; exit 1 ;;
esac
