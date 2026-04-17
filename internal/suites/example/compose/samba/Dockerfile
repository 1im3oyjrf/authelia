FROM alpine:3.20@sha256:30b6ec4eb5d71e99154c064f7a0af9a2b60d50110be5911db32ab0cdf90e448e

RUN \
apk add --no-cache \
	bash \
	krb5 \
	ldb-tools \
	openldap-clients \
	openssl \
	samba-dc \
	supervisor

CMD ["/init.sh", "setup"]
