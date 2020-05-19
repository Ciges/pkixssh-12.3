#	Placed in the Public Domain.

tid="proxy connect with privsep in FIPS mode"

if test -z "$OPENSSL_FIPS" ; then
  fail "test is not run in FIPS environment"
fi


cp $OBJ/sshd_proxy $OBJ/sshd_proxy.orig
echo 'UsePrivilegeSeparation yes' >> $OBJ/sshd_proxy

echo "= UsePrivilegeSeparation yes" >> $TEST_SSH_LOGFILE
$SSH -F $OBJ/ssh_proxy 999.999.999.999 :
if test $? -ne 0; then
  fail "ssh privsep+proxyconnect failed"
fi


cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy
echo 'UsePrivilegeSeparation sandbox' >> $OBJ/sshd_proxy

echo "= UsePrivilegeSeparation sandbox" >> $TEST_SSH_LOGFILE
$SSH -F $OBJ/ssh_proxy 999.999.999.999 :
if test $? -ne 0; then
  warn "ssh privsep/sandbox+proxyconnect failed"
fi
