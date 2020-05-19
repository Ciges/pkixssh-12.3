#
# Copyright (c) 2002-2018 Roumen Petrov, Sofia, Bulgaria
# All rights reserved.
#
# Redistribution and use of this script, with or without modification, is
# permitted provided that the following conditions are met:
#
# 1. Redistributions of this script must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
#  EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# DESCRIPTION: Test client authentication:
#  - "IdentityFile" contain private key and X.509 certificate;
#  - "AuthorizedKeysFile" contain certificate Subject;
#  - authorization against exact intermediate CA certificate in
#    server X.509 store (legacy public key algorithm);
#  - not applicable for RFC6187 key algorithms.


# ===
#env. vars:
#  SSH_CLIENTKEY
#  catype
#  type
testDNautorizations2 () {
  identity_file="${SSH_CLIENTKEY}-${type}"

  creX509AuthorizedKeysFile "${identity_file}" || return $?

  expect_success=:
  test "$type" != "$catype" && expect_success=false
  if $expect_success ; then
    runTest "${extd}${type}${norm}" \
      "${identity_file}"\
      "" ""
  else
    runTest "${type}" \
      "${identity_file}" \
      "${warn}!${norm}" "Yes"
  fi
}


# ===
#env. vars:
#  catype
do_test_catype () {
  echo "  - authorization by X.509 ${attn}Subject${norm} against CA key ${attn}${catype}${norm}"

  for type in ${SSH_SIGN_TYPES}; do
    testDNautorizations2 "${catype}" "${type}" || return $?
  done
}


# ===

do_test () {
  echo "* ${extd}against ${attn}CACertificatePath${norm}:"

  CRT_TEST_DIR="${SSH_CAROOT}/crt-test"

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile /file/not/found
CACertificatePath ${CRT_TEST_DIR}
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  TEST_CLIENT_CFG="\
PubkeyAlgorithms x509v3-sign-*
"

  TEST_SSH_LEGACY_CLIENTKEYS=
  for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS; do
    case $SSH_CLIENTKEY in
    testid_rsa*);;
    testid_dsa*);;
    *) continue;;
    esac
    TEST_SSH_LEGACY_CLIENTKEYS="$TEST_SSH_LEGACY_CLIENTKEYS $SSH_CLIENTKEY"
  done

  runSSHdaemon || return $?
  (
    for SSH_CLIENTKEY in $TEST_SSH_LEGACY_CLIENTKEYS; do
      printSeparator
      echo "Begin test with base key_file ${attn}${SSH_CLIENTKEY}${norm} ..."

      if test ! -d "${CRT_TEST_DIR}"; then
        mkdir "$CRT_TEST_DIR" || exit $?
      fi
      rm -rf "${CRT_TEST_DIR}/"* 2>/dev/null

      for catype in ${SSH_SIGN_TYPES}; do
        ( cd "$CRT_TEST_DIR" &&
          rm -f "$CRT_TEST_DIR"/* &&
          for level in 0; do
            cre_hash_link "$SSH_CAROOT/crt/$CAKEY_PREFIX-root${level}.crt.pem" || exit $?
          done
          cre_hash_link "$SSH_CAROOT/crt/$CAKEY_PREFIX-$catype.crt.pem"
        ) &&
        do_test_catype; retval=$?
        rm -f "$CRT_TEST_DIR"/*
        if test $retval -ne 0; then
          break
        fi
      done

      rmdir "${CRT_TEST_DIR}"
      if test $retval -ne 0; then
        exit $retval
      fi
    done

    exit 0
  ); retval=$?
  killSSHdaemon
  return $retval
}
