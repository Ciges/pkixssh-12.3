#
# Copyright (c) 2006-2018 Roumen Petrov, Sofia, Bulgaria
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
#  - "IdentityFile" contain private key and self-issued X.509 certificate;
#  - "AuthorizedKeysFile" contain encoded either public key or X.509
#   certificate or certificate Distinguished Name.
#


# ===
#args:
#  $1 - request to fail flag for encoded identity
#  $2 - request to fail flag for distinguished name
test_self() {

  case $1 in
    Y|y|Yes|yes|YES|1)
      encoded_fail=yes;;
    *)
      encoded_fail=no;;
  esac
  case $2 in
    Y|y|Yes|yes|YES|1)
      dn_msg="${warn}Distinguished Name${norm}";;
    *)
      dn_msg="${extd}Distinguished Name${norm}";;
  esac

    for type in rsa dsa ; do
      SSH_CLIENTKEY="selfid_$type"

      identity_file="$SSH_CLIENTKEY-$type"
      echo "  using identity file $identity_file"

      if test yes = $encoded_fail; then
        blob_msg="encoded ${warn}public${norm} key"
      else
        blob_msg="encoded ${extd}public${norm} key"
      fi
      # public key
      cat "$SSH_CLIENTKEY.pub" > "$AUTHORIZEDKEYSFILE" &&
      runTest "$type" "$identity_file" "$blob_msg" $encoded_fail \
      || return $?

      if test yes = $encoded_fail; then
        blob_msg="encoded ${warn}X.509${norm} certificate"
      else
        blob_msg="encoded ${extd}X.509${norm} certificate"
      fi
      # X.509 certificate
      cat "$identity_file.pub" > "$AUTHORIZEDKEYSFILE" &&
      runTest "$type" "$identity_file" "$blob_msg" $encoded_fail \
      || return $?

      sshkeytype=`getSSHkeyType "$identity_file"` || return $?
      subject=`getSubject "$identity_file"` || return $?
      # X.509 certificate distinguished name
      echo "$sshkeytype Subject: $subject" > "$AUTHORIZEDKEYSFILE" &&
      runTest "$type" "$identity_file" "$dn_msg" "$2" \
      || return $?
    done
}

# ===

test_store () {
  retval=0
  echo "  - ${attn}with${norm} self-issued trusted by ${extd}x509store${norm}:"
  printSeparator

  cat selfid_*.crt > $CWD/selfid-bundle

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
KeyAllowSelfIssued no
CACertificateFile $CWD/selfid-bundle
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "no" "no"
  ); retval=$?
  killSSHdaemon
  rm -f $CWD/selfid-bundle
  return $retval
}

# ===

test_pkey_no () {
  retval=0
  echo "  - ${attn}without${norm} allowed self-issued trusted by ${extd}public identity${norm}:"
  printSeparator

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
KeyAllowSelfIssued no
CACertificateFile /file/not/found
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "yes" "yes"
  ); retval=$?
  killSSHdaemon
  return $retval
}

# ===

test_pkey_yes () {
  retval=0
  echo "  - ${attn}with${norm} allowed self-issued trusted by ${extd}public identity${norm}:"
  printSeparator

  echo "${extd}check if exist X.509 verification bug${norm} ..."
  # (see mail thread "1.0.2beta2 and X.509 certificate verification")
  # expected if only
  # 'error 18 at 0 depth lookup:self signed certificate'
  # buggy if return extra:
  # 'error 20 at 0 depth lookup:unable to get local issuer certificate'
  if $OPENSSL verify "$SSH_CAROOT/crt/$CAKEY_PREFIX-root0.crt.pem" | grep 'error 20' > /dev/null ; then
    echo "${warn}skipped due to openssl verification bug${norm}" >&2
    echo "(see email thread ${attn}1.0.2beta2 and X.509 certificate verification${norm})" >&2
    return 0
  fi
  echo "... ${extd}none found!${norm}"

  printSeparator

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
KeyAllowSelfIssued yes
CACertificateFile /file/not/found
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "no" "yes"
  ); retval=$?
  killSSHdaemon
  return $retval
}

# ===

test_pkey () {
  retval=0
  echo "  - ${attn}with${norm} self-signed allowed by encoded ${extd}public identity${norm}:"
  printSeparator

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
AllowedCertPurpose skip
#Unsupported options:
#KeyAllowSelfIssued no
#CACertificateFile /file/not/found
#CACertificatePath /path/not/found
#CARevocationFile  /crlfile/not/found
#CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    test_self "no" "yes"
  ); retval=$?
  killSSHdaemon
  return $retval
}

# ===
SELFtestBREAK() {
  echo
  rm -f $CWD/selfid-bundle
  testBREAK
}

trap SELFtestBREAK HUP INT QUIT ABRT TERM || exit 1


# ===

do_test () {
  echo "* ${extd}self-signed${norm}:"

  test_store &&
  test_pkey_no &&
  test_pkey_yes
}
