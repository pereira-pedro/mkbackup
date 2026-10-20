# Rebuild the signed Ubuntu source package with two narrowly scoped BPF fixes.
# Build dependencies stay out of the runtime image; distro security patches and
# package hardening flags remain in use.
FROM ubuntu:24.04 AS ftp-build
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dpkg-dev build-essential \
    && DEBIAN_FRONTEND=noninteractive apt-get build-dep -y --no-install-recommends vsftpd
WORKDIR /build
RUN apt-get source vsftpd
COPY patches/vsftpd-seccomp.patch /build/seccomp.patch
RUN cd /build/vsftpd-* \
    && patch --batch --forward -p1 < /build/seccomp.patch \
    && dpkg-buildpackage -b -us -uc \
    && install -D -m 0755 debian/vsftpd/usr/sbin/vsftpd /out/vsftpd

FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server openssl libnss-extrausers python3 python3-cryptography gunicorn vsftpd \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && sed -i -E '/^(passwd|group|shadow):/ s/$/ extrausers/' /etc/nsswitch.conf \
    && install -d -m 0755 /srv/sftp /archive /receipts /var/lib/extrausers /usr/local/lib/mkbackup \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/mkbackup-enrollment
COPY --from=ftp-build /out/vsftpd /usr/sbin/vsftpd
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
