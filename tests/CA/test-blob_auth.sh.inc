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
#  - "IdentityFile" contain private key and x509 certificate;
#  - "AuthorizedKeysFile" contain encoded either X.509 certificate
#    or public key.
#


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testX509autorization () {
  identity_file="$SSH_CLIENTKEY-$type"
  if test ! -r "$identity_file" ; then
    error_file_not_readable "$identity_file"; return $?
  fi

  echo "  using identity file $identity_file"

  "$TEST_SSH_SSHKEYGEN" -f "$identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || return $?
  runTest "$type" "$identity_file"\
    "${extd}valid${norm}" || return $?

  blob=`cat "$AUTHORIZEDKEYSFILE"`
  echo $blob | cut -c 1-50 > "$AUTHORIZEDKEYSFILE"
  runTest "$type" "$identity_file"\
    "${warn}invalid${norm}" "Yes" || return $?
}


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testPUBKEYautorization () {
  base_identity_file="$SSH_CLIENTKEY"
  if test ! -r "$base_identity_file" ; then
    error_file_not_readable "$base_identity_file"; return $?
  fi
  identity_file="$base_identity_file-$type"
  if test ! -r "$identity_file" ; then
    error_file_not_readable "$identity_file"; return $?
  fi

  echo "  using $base_identity_file to autorize X.509/$type"

  "$TEST_SSH_SSHKEYGEN" -f "$base_identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || return $?
  runTest "$type" "$identity_file"\
    "${extd}valid${norm}" || return $?

  blob=`cat "$AUTHORIZEDKEYSFILE"`
  echo $blob | cut -c 1-50 > "$AUTHORIZEDKEYSFILE"
  runTest "$type" "$identity_file"\
    "${warn}invalid${norm}" "Yes" || return $?
}


# ===

do_test () {
  retval=0
  echo "* ${extd}with ${attn}CACertificateFile${norm} and"
  echo "* ${extd}authorization${norm} by encoded ${attn}public identity${norm}:"

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile $SSH_CAROOT/$CACERTFILE
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS; do
      printSeparator
      echo "Begin tests with authorization by encoded ${attn}X.509${norm} certificate ..."

      for type in $SSH_SIGN_TYPES; do
        testX509autorization || exit $?
      done

      printSeparator
      echo "Begin tests with authorization by encoded ${attn}public${norm} key ..."
      for type in $SSH_SIGN_TYPES; do
        testPUBKEYautorization || exit $?
      done

    done
  ); retval=$?
  killSSHdaemon
  return $retval
}
