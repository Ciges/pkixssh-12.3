#
# spec file for pkixssh package
#
# This is free software; see Copyright file in the source
# distribution for precise wording.
#
# Copyright (c) 2019 Roumen Petrov
#

# Do we want to enable building with ldap? (1=yes 0=no)
%global enable_ldap 1

# Do we use FIPS capable OpenSSL library ? (1=yes 0=no)
%global enable_openssl_fips 1


# norootforbuild

Url:		https://roumenpetrov.info/secsh/

Name:		pkixssh
Summary:	PKIX-SSH, Advanced secure shell implementation
Version:	12.3
Release:	1
License:	BSD
Group:		Productivity/Networking/SSH

PreReq:		permissions
Requires(pre):	%insserv_prereq %fillup_prereq

BuildRequires:	libselinux-devel
BuildRequires:	zlib-devel
BuildRequires:	pam-devel
BuildRequires:	libopenssl-devel openssl
%if %{enable_ldap}
BuildRequires:	openldap2-devel openldap2 openldap2-client
%endif
%if %{enable_openssl_fips}
BuildRequires:	fipscheck-devel fipscheck
# TODO: to run in FIPS mode, but which version 1_0_0 or 1_1?
#BuildRequires:	libopenssl<VER>-hmac
#Requires:	libopenssl<VER>-hmac
%endif
BuildRequires:	groff
BuildRoot:	%{_tmppath}/%{name}-%{version}-build

Source0:	https://roumenpetrov.info/secsh/src/%{name}-%{version}.tar.xz


# Default values for additional components

%define ssh_sysconfdir		%{_sysconfdir}/ssh
%define ssh_libexecdir		%{_libexecdir}/ssh
%define ssh_privsep_path	/var/lib/sshd

# Define the UID/GID to use for privilege separation
%define sshd_gid	475
%define sshd_uid	472

%if ! %{defined _fillupdir}
 %define _fillupdir /var/adm/fillup-templates
%endif


%description
Ssh (Secure Shell) is a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.


%prep
%setup -q
%patch0 -p1


%build
%configure \
  --prefix=/usr \
  --libexecdir=%{ssh_libexecdir} \
  --sysconfdir=%{ssh_sysconfdir} \
  --mandir=%{_mandir} \
%if %{enable_ldap}
  --enable-ldap --with-ldap-libexecdir=/usr/sbin \
%else
  --disable-ldap \
%endif
  --with-pam \
  --with-privsep-path=%{ssh_privsep_path}
make


%check
%if %{enable_ldap}
LDAP_MODULEDIR=%{_libdir}/openldap
export LDAP_MODULEDIR
%endif
TERM=dumb \
make check


%install
make install DESTDIR=%{buildroot}

install -d %{buildroot}/etc/pam.d/
install -m644 contrib/sshd.pam.generic %{buildroot}/etc/pam.d/sshd

install -d %{buildroot}/etc/init.d/
install -m744 contrib/suse/rc.sshd %{buildroot}/etc/init.d/sshd

install -d %{buildroot}%{_fillupdir}
install -m744 contrib/suse/sysconfig.ssh %{buildroot}%{_fillupdir}


#obsolete#%clean


%pre
/usr/sbin/groupadd -g %{sshd_gid} -o -r sshd 2> /dev/null || :
/usr/sbin/useradd -r -o -g sshd -u %{sshd_uid} -s /bin/false -c "SSH daemon" -d %{ssh_privsep_path} sshd 2> /dev/null || :


%post
/usr/bin/ssh-keygen -A
%set_permissions %{ssh_sysconfdir}/ssh_config
%set_permissions %{ssh_sysconfdir}/sshd_config
%set_permissions %{ssh_sysconfdir}/moduli
%set_permissions %{ssh_libexecdir}/ssh-keysign
%{fillup_and_insserv -n -y ssh sshd}


%verifyscript
%verify_permissions -e %{ssh_sysconfdir}/ssh_config
%verify_permissions -e %{ssh_sysconfdir}/sshd_config
%verify_permissions -e %{ssh_sysconfdir}/moduli
%verify_permissions -e %{ssh_libexecdir}/ssh-keysign


%preun
%stop_on_removal sshd


%postun
%restart_on_update sshd
%{insserv_cleanup}


%files
%defattr(-,root,root)
%if 0%{?suse_version} >= 1500
%license LICENCE
%endif
%doc CREDITS LICENCE OVERVIEW PROTOCOL* README*
%doc TODO
%attr(0755,root,root) %dir %{ssh_sysconfdir}
%attr(0644,root,root) %verify(not mode) %config(noreplace) %{ssh_sysconfdir}/ssh_config
%attr(0600,root,root) %verify(not mode) %config(noreplace) %{ssh_sysconfdir}/sshd_config
%attr(0600,root,root) %verify(not mode) %config(noreplace) %{ssh_sysconfdir}/moduli
%attr(0644,root,root) %config(noreplace) /etc/pam.d/sshd
%attr(0755,root,root) %config /etc/init.d/sshd
%attr(0755,root,root) %{_bindir}/scp
%attr(0755,root,root) %{_bindir}/sftp
%attr(0755,root,root) %{_bindir}/ssh
%attr(0755,root,root) %{_bindir}/ssh-add
%attr(0755,root,root) %{_bindir}/ssh-agent
%attr(0755,root,root) %{_bindir}/ssh-keygen
%attr(0755,root,root) %{_bindir}/ssh-keyscan
%attr(0755,root,root) %{_sbindir}/sshd
%attr(0755,root,root) %dir %{ssh_libexecdir}
%attr(0755,root,root) %{ssh_libexecdir}/sftp-server
#TODO setuid
#%attr(4711,root,root) %verify(not mode) %{ssh_libexecdir}/ssh-keysign
%attr(0755,root,root) %verify(not mode) %{ssh_libexecdir}/ssh-keysign
%attr(0755,root,root) %{ssh_libexecdir}/ssh-pkcs11-helper
%attr(0644,root,root) %doc %{_mandir}/man1/scp.1*
%attr(0644,root,root) %doc %{_mandir}/man1/sftp.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh-add.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh-agent.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh-keygen.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh-keyscan.1*
%attr(0644,root,root) %doc %{_mandir}/man5/moduli.5*
%attr(0644,root,root) %doc %{_mandir}/man5/ssh_config.5*
%attr(0644,root,root) %doc %{_mandir}/man5/ssh_engine.5*
%attr(0644,root,root) %doc %{_mandir}/man5/sshd_config.5*
%attr(0644,root,root) %doc %{_mandir}/man8/sftp-server.8*
%attr(0644,root,root) %doc %{_mandir}/man8/ssh-keysign.8*
%attr(0644,root,root) %doc %{_mandir}/man8/ssh-pkcs11-helper.8*
%attr(0644,root,root) %doc %{_mandir}/man8/sshd.8*
%attr(0755,root,root) %dir %{_fillupdir}
%attr(0644,root,root) %{_fillupdir}/sysconfig.ssh
