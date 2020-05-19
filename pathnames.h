/* $OpenBSD: pathnames.h,v 1.28 2018/02/23 15:58:37 markus Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2002-2019 Roumen Petrov.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define ETCDIR				"/etc"

#ifndef SSHDIR
#define SSHDIR				ETCDIR "/ssh"
#endif

#ifndef SSHBINDIR
#define SSHBINDIR			"/usr/bin"
#endif

#ifndef SSHLIBEXECDIR
#define SSHLIBEXECDIR			"/usr/libexec"
#endif

#ifndef _PATH_SSH_PIDDIR
#define _PATH_SSH_PIDDIR		"/var/run"
#endif

/*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#define _PATH_SSH_SYSTEM_HOSTFILE	SSHDIR "/ssh_known_hosts"
/* backward compat for protocol 2 */
#define _PATH_SSH_SYSTEM_HOSTFILE2	SSHDIR "/ssh_known_hosts2"

/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#define _PATH_SERVER_CONFIG_FILE	SSHDIR "/sshd_config"
#define _PATH_HOST_CONFIG_FILE		SSHDIR "/ssh_config"
#define _PATH_HOST_DSA_KEY_FILE		SSHDIR "/ssh_host_dsa_key"
#define _PATH_HOST_ECDSA_KEY_FILE	SSHDIR "/ssh_host_ecdsa_key"
#define _PATH_HOST_ED25519_KEY_FILE	SSHDIR "/ssh_host_ed25519_key"
#define _PATH_HOST_XMSS_KEY_FILE	SSHDIR "/ssh_host_xmss_key"
#define _PATH_HOST_RSA_KEY_FILE		SSHDIR "/ssh_host_rsa_key"
#define _PATH_DH_MODULI			SSHDIR "/moduli"

#define _PATH_SSH_PROGRAM		SSHBINDIR "/ssh"

/*
 * The process id of the daemon listening for connections is saved here to
 * make it easier to kill the correct daemon when necessary.
 */
#define _PATH_SSH_DAEMON_PID_FILE	_PATH_SSH_PIDDIR "/sshd.pid"

/*
 * The directory in user's home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#define _PATH_SSH_USER_DIR		".ssh"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#define _PATH_SSH_USER_HOSTFILE		"~/" _PATH_SSH_USER_DIR "/known_hosts"
/* backward compat for protocol 2 */
#define _PATH_SSH_USER_HOSTFILE2	"~/" _PATH_SSH_USER_DIR "/known_hosts2"

/*
 * Name of the default file containing client-side authentication key. This
 * file should only be readable by the user him/herself.
 */
#define _PATH_SSH_CLIENT_ID_DSA		_PATH_SSH_USER_DIR "/id_dsa"
#define _PATH_SSH_CLIENT_ID_ECDSA	_PATH_SSH_USER_DIR "/id_ecdsa"
#define _PATH_SSH_CLIENT_ID_RSA		_PATH_SSH_USER_DIR "/id_rsa"
#define _PATH_SSH_CLIENT_ID_ED25519	_PATH_SSH_USER_DIR "/id_ed25519"
#define _PATH_SSH_CLIENT_ID_XMSS	_PATH_SSH_USER_DIR "/id_xmss"

/*
 * Configuration file in user's home directory.  This file need not be
 * readable by anyone but the user him/herself, but does not contain anything
 * particularly secret.  If the user's home directory resides on an NFS
 * volume where root is mapped to nobody, this may need to be world-readable.
 */
#define _PATH_SSH_USER_CONFFILE		_PATH_SSH_USER_DIR "/config"

#ifdef USE_OPENSSL_ENGINE
/*
 * Engine configuration file in user's home directory. Same rules as
 * for user config file.
 */
#define _PATH_SSH_ENGINE_CONFFILE	_PATH_SSH_USER_DIR "/engine"
#endif

/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user's home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#define _PATH_SSH_USER_PERMITTED_KEYS	_PATH_SSH_USER_DIR "/authorized_keys"

/* backward compat for protocol v2 */
#define _PATH_SSH_USER_PERMITTED_KEYS2	_PATH_SSH_USER_DIR "/authorized_keys2"

/*
 * Per-user and system-wide ssh "rc" files.  These files are executed with
 * /bin/sh before starting the shell or command if they exist.  They will be
 * passed "proto cookie" as arguments if X11 forwarding with spoofing is in
 * use.  xauth will be run if neither of these exists.
 */
#define _PATH_SSH_USER_RC		_PATH_SSH_USER_DIR "/rc"
#define _PATH_SSH_SYSTEM_RC		SSHDIR "/sshrc"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#define _PATH_SSH_HOSTS_EQUIV		SSHDIR "/shosts.equiv"
#define _PATH_RHOSTS_EQUIV		"/etc/hosts.equiv"

/* Location of askpass */
#define _PATH_SSH_ASKPASS		SSHLIBEXECDIR "/ssh-askpass"

/* Location of ssh-keysign for hostbased authentication */
#define _PATH_SSH_KEY_SIGN		SSHLIBEXECDIR "/ssh-keysign"

/* Location of ssh-pkcs11-helper to support keys in tokens */
#define _PATH_SSH_PKCS11_HELPER		SSHLIBEXECDIR "/ssh-pkcs11-helper"

/* xauth for X11 forwarding */
#ifndef _PATH_XAUTH
#define _PATH_XAUTH			"/usr/X11R6/bin/xauth"
#endif

/* UNIX domain socket for X11 server; displaynum will replace %u */
#ifndef _PATH_UNIX_X
#define _PATH_UNIX_X "/tmp/.X11-unix/X%u"
#endif

/* for scp */
#ifndef _PATH_CP
#define _PATH_CP			"cp"
#endif

/* for external sftp sever */
#define _PATH_SFTP_SERVER		SSHLIBEXECDIR "/sftp-server"

/* chroot directory for unprivileged user when UsePrivilegeSeparation=yes */
#ifndef _PATH_PRIVSEP_CHROOT_DIR
#define _PATH_PRIVSEP_CHROOT_DIR	"/var/empty"
#endif

/* for passwd change */
#ifndef _PATH_PASSWD_PROG
#define _PATH_PASSWD_PROG             "/usr/bin/passwd"
#endif

#ifndef _PATH_LS
#define _PATH_LS			"ls"
#endif


#ifndef SSHCADIR
#define SSHCADIR			SSHDIR "/ca"
#endif

/* x509 user store */
#define _PATH_USERCA_CERTIFICATE_FILE	"~/" _PATH_SSH_USER_DIR "/ca-bundle.crt"
#define _PATH_USERCA_CERTIFICATE_PATH	"~/" _PATH_SSH_USER_DIR "/crt"
#define _PATH_USERCA_REVOCATION_FILE	"~/" _PATH_SSH_USER_DIR "/ca-bundle.crl"
#define _PATH_USERCA_REVOCATION_PATH	"~/" _PATH_SSH_USER_DIR "/crl"

/* x509 system store */
#define _PATH_CA_CERTIFICATE_FILE	SSHCADIR "/ca-bundle.crt"
#define _PATH_CA_CERTIFICATE_PATH	SSHCADIR "/crt"
#define _PATH_CA_REVOCATION_FILE	SSHCADIR "/ca-bundle.crl"
#define _PATH_CA_REVOCATION_PATH	SSHCADIR "/crl"
