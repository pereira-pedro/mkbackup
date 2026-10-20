FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server openssl libnss-extrausers python3 python3-cryptography gunicorn vsftpd \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && sed -i -E '/^(passwd|group|shadow):/ s/$/ extrausers/' /etc/nsswitch.conf \
    && install -d -m 0755 /srv/sftp /archive /receipts /var/lib/extrausers /usr/local/lib/mkbackup \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/mkbackup-enrollment
COPY sshd_config /etc/ssh/mkbackup.conf
COPY vsftpd-mkbackup.conf /etc/vsftpd-mkbackup.conf
COPY container/pam-ftp /etc/pam.d/mkbackup-ftp
COPY container/ /usr/local/lib/mkbackup/
COPY mikrotik/ /usr/local/share/mkbackup/mikrotik/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod 0555 /usr/local/bin/docker-entrypoint \
    && find /usr/local/lib/mkbackup -type f -exec chmod 0444 {} +
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 2222/tcp 2121/tcp 8080/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python3", "/usr/local/lib/mkbackup/healthcheck.py"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["sftp"]
