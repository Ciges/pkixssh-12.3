#
# Copyright (c) 2011-2018 Roumen Petrov, Sofia, Bulgaria
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
#  - "IdentityFile" contain private key and optional x509 certificates;
#  - "AuthorizedKeysFile" contain certificate BLOB.
#  - server accept different publickey algorithms based on certificates.
#  - client use different digest algorithms.
#  - test is not applicable for ecdsa
# Note that "Host-Based Authentication" we cannot test without to install.
#


# ===
#env. vars:
#  alg
testAlgFmt () {
  printSeparator

# NOTE:
# The default for certificates with RSA key is:
# - draft-ietf-secsh-transport-NN.txt where NN <= 12:
#   X509KeyAlgorithm x509v3-sign-rsa,rsa-md5
#   X509KeyAlgorithm x509v3-sign-rsa,rsa-sha1
# - rfc6187:
#   X509KeyAlgorithm x509v3-ssh-rsa,sha1,ssh-rsa
# The default for certificates with DSA key is:
# - draft-ietf-secsh-transport-NN.txt where NN <= 12:
#   X509KeyAlgorithm x509v3-sign-dss,dss-asn1
#   X509KeyAlgorithm x509v3-sign-dss,dss-raw
# - rfc6187:
#   X509KeyAlgorithm x509v3-ssh-dss,dss-raw,ssh-dss
# Not applicable for x509v3-ecdsa-sha2-*

  case $alg in
    x509v3-sign-rsa*) fmt_list="rsa-sha1 rsa-md5";;
    x509v3-sign-dss*) fmt_list="dss-raw dss-asn1";;
    x509v3-ssh-rsa*)  fmt_list="rsa-sha1,ssh-rsa";;
    x509v3-ssh-dss*)  fmt_list="dss-raw,ssh-dss";;
  esac

  for fmt_srv in $fmt_list; do
    echo "  - server: only ${attn}${alg}${norm} algorithm with ${attn}${fmt_srv}${norm} digest"

    creTestSSHDcfgFile
(
    cat <<EOF
CACertificateFile $SSH_CAROOT/$CACERTFILE
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found

PubkeyAlgorithms $alg
X509KeyAlgorithm $alg,$fmt_srv
EOF
    # TODO public key file contain default X.509 algorithm!
    # To read authorized keys we has to know other algorithms,
    # so let describe all of them with fake signature.
    case $alg in
    x509v3-sign-rsa*) echo "X509KeyAlgorithm x509v3-ssh-rsa,rsa-sha1,fake-ssh-rsa"  ;;
    x509v3-sign-dss*) echo "X509KeyAlgorithm x509v3-ssh-dss,dss-raw,fake-ssh-dss"   ;;
    x509v3-ssh-rsa*)  echo "X509KeyAlgorithm x509v3-sign-rsa,rsa-sha1,fake-sign-rsa";;
    x509v3-ssh-dss*)  echo "X509KeyAlgorithm x509v3-sign-dss,dss-raw,fake-sign-dss" ;;
    esac
) >> "$SSHD_CFG"
    case $fmt_srv in
      *md5)
        if test -n "$OPENSSL_FIPS"; then
          if "$TEST_SSH_SSHD" -f "$SSHD_CFG" -t >> "$SSHD_LOG" 2>&1; then
            echo "    server in ${attn}FIPS${norm} mode - accept ${attn}$fmt_srv${norm} digest!"
            return 99
          else
            echo "    server in ${attn}FIPS${norm} mode - skipping ..."
            continue
          fi
        fi
        ;;
    esac


    runSSHdaemon || return $?
    (
      for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS; do
        case $SSH_CLIENTKEY in
          *ecc*) continue;;
          *rsa) keytype="rsa";;
          *dsa) keytype="dsa";;
          *)    echo "${warn}unknown client key type : $SSH_CLIENTKEY${norm}"
                exit 1;;
        esac
        case $alg in
          x509v3-*-rsa*) test "$keytype" = "rsa" || continue;;
          x509v3-*-dss*) test "$keytype" = "dsa" || continue;;
          *)
            echo "${warn}unknown X.509 alg${norm}" >&2
            exit 1;;
        esac

        for type in $SSH_SIGN_TYPES; do
          identity_file="$SSH_CLIENTKEY-$type"
          "$TEST_SSH_SSHKEYGEN" -f "$identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || exit $?

          for fmt_cln in $fmt_list; do
            TEST_CLIENT_CFG="\
X509KeyAlgorithm $alg,$fmt_cln
"
            if test $fmt_srv = $fmt_cln; then
              must_fail=no
              typemsg="$identity_file $fmt_cln"
            else
              must_fail=yes
              typemsg="$identity_file $fmt_cln ${warn}!${norm}"
            fi
            must_fail_err_txt=

            if test -n "$OPENSSL_FIPS"; then
              case $fmt_cln in
                *md5)
                  typemsg="$identity_file $fmt_cln ${warn}FIPS mode!${norm}"
                  must_fail_err_txt='rsa-md5 in not enabled in FIPS mode'
                  ;;
              esac
            fi

            runTest "$typemsg" \
              "$identity_file" "" $must_fail $must_fail_err_txt || exit $?
          done
        done
      done
    ); retval=$?
    killSSHdaemon

    test $retval -ne 0 && break
  done

  return $retval
}


# ===

do_test () {
  retval=0
  echo "* ${extd}against ${attn}CACertificateFile${norm} and different digest ${attn}algorithms${norm}:"

  for alg in \
    $SSH_ALGS_X509_RSA \
    $SSH_ALGS_X509_DSA \
  ; do
    testAlgFmt; retval=$?
    test $retval -ne 0 && break
  done
  return $retval
}
