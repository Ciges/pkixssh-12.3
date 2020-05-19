#	Placed in the Public Domain.

tid="try ciphers in FIPS mode"

if test -z "$OPENSSL_FIPS" ; then
  fail "test is not run in FIPS environment"
fi


fips_ciphers=`$SSH -Q cipher`
other_ciphers=
for v in `unset OPENSSL_FIPS; $SSH -Q cipher` ; do
  for f in $fips_ciphers ''; do
    test "x$v" = "x$f" && break
  done
  test -z "$f" && other_ciphers="$other_ciphers $v"
done

fips_macs=`$SSH -Q mac`
other_macs=
for v in `unset OPENSSL_FIPS; $SSH -Q mac` ; do
  for f in $fips_macs ''; do
    test "x$v" = "x$f" && break
  done
  test -z "$f" && other_macs="$other_macs $v"
done


cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak

update_sshd_proxy() {
  cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
  echo "Ciphers=$1" >> $OBJ/sshd_proxy
  echo "MACs=$2"    >> $OBJ/sshd_proxy
}


for c in $fips_ciphers; do
  for m in $fips_macs; do
    msg="fips-cipher $c fips-mac $m"
    trace "$msg"
    verbose "test $tid: $msg"
    update_sshd_proxy $c $m
    $SSH -F $OBJ/ssh_proxy -m $m -c $c somehost :
    if test 0 -ne $?; then
      fail "ssh failed with mac $m cipher $c"
    fi
  done
done

# non-fips mac should fail
for c in $fips_ciphers; do
  for m in $other_macs; do
    msg="fips-cipher $c mac $m"
    trace "$msg"
    verbose "negative test $tid: $msg"
    update_sshd_proxy $c $m
    $SSH -F $OBJ/ssh_proxy -m $m -c $c somehost : >>$TEST_SSH_LOGFILE 2>&1
    if test 0 -eq $?; then
      fail "ssh succeeded with mac $m cipher $c - nok"
    fi
  done
done

# non-fips cipher should fail
for c in $other_ciphers; do
  for m in $fips_macs $other_macs; do
    msg="cipher $c mac $m"
    trace "$msg"
    verbose "negative test $tid: $msg"
    update_sshd_proxy $c $m
    $SSH -F $OBJ/ssh_proxy -m $m -c $c somehost : >>$TEST_SSH_LOGFILE 2>&1
    if test 0 -eq $?; then
      fail "ssh succeeded with mac $m cipher $c - nok"
    fi
  done
done
