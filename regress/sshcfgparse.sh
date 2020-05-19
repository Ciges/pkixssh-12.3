#	$OpenBSD: sshcfgparse.sh,v 1.5 2019/07/23 13:32:48 dtucker Exp $
#	Placed in the Public Domain.

tid="ssh config parse"

verbose "reparse minimal config"
(${SSH} -d -F $OBJ/ssh_config somehost >$OBJ/ssh_config.1 &&
 ${SSH} -d -F $OBJ/ssh_config.1 somehost >$OBJ/ssh_config.2 &&
 diff $OBJ/ssh_config.1 $OBJ/ssh_config.2) || fail "reparse minimal config"

verbose "ssh -W opts"
f=`${SSH} -dF $OBJ/ssh_config host | awk '/exitonforwardfailure/{print $2}'`
test "$f" = "no" || fail "exitonforwardfailure default"
f=`${SSH} -dF $OBJ/ssh_config -W a:1 h | awk '/exitonforwardfailure/{print $2}'`
test "$f" = "yes" || fail "exitonforwardfailure enable"
f=`${SSH} -dF $OBJ/ssh_config -W a:1 -o exitonforwardfailure=no h | \
    awk '/exitonforwardfailure/{print $2}'`
test "$f" = "no" || fail "exitonforwardfailure override"

f=`${SSH} -dF $OBJ/ssh_config host | awk '/clearallforwardings/{print $2}'`
test "$f" = "no" || fail "clearallforwardings default"
f=`${SSH} -dF $OBJ/ssh_config -W a:1 h | awk '/clearallforwardings/{print $2}'`
test "$f" = "yes" || fail "clearallforwardings enable"
f=`${SSH} -dF $OBJ/ssh_config -W a:1 -o clearallforwardings=no h | \
    awk '/clearallforwardings/{print $2}'`
test "$f" = "no" || fail "clearallforwardings override"

verbose "user first match"
user=`awk '$1=="User" {print $2}' $OBJ/ssh_config`
f=`${SSH} -dF $OBJ/ssh_config host | awk '/^user /{print $2}'`
test "$f" = "$user" || fail "user from config, expected '$user' got '$f'"
f=`${SSH} -dF $OBJ/ssh_config -o user=foo -l bar baz@host | awk '/^user /{print $2}'`
test "$f" = "foo" || fail "user first match -oUser, expected 'foo' got '$f' "
f=`${SSH} -dF $OBJ/ssh_config -lbar baz@host user=foo baz@host | awk '/^user /{print $2}'`
test "$f" = "bar" || fail "user first match -l, expected 'bar' got '$f'"
f=`${SSH} -dF $OBJ/ssh_config baz@host -o user=foo -l bar baz@host | awk '/^user /{print $2}'`
test "$f" = "baz" || fail "user first match user@host, expected 'baz' got '$f'"

# cleanup
rm -f $OBJ/ssh_config.[012]
