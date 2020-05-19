#! /bin/sh
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
# DESCRIPTION: Create test certificate(s).
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/3-cre_certs.sh$//'`
. "${SCRIPTDIR}shell.rc"
. "${SCRIPTDIR}functions"
. "${SCRIPTDIR}config"

usage () {
  cat <<EOF
usage: $0 <options>
  -f[ile]	[ssh]key_file_name
  -t[ype]	certificate type: client, server, ocsp(if enabled)
  -n[ame]	"base" common name
EOF
  exit 1
}

test "x$TEST_SSH_SSHKEYGEN" = "x" && { echo "${warn}Please define ${attn}TEST_SSH_SSHKEYGEN${norm}" >&2 ; exit 1; }
test -z "$1" && usage


SSH_SELFCERT=no

while test -n "$1"; do
  case $1 in
    -f|\
    -file)
      shift
      if test -z "$1"; then
        usage
      fi
      if test -n "${SSH_BASE_KEY}"; then
        usage
      fi
      SSH_BASE_KEY="$1"
      shift
      ;;

    -t|\
    -type)
      shift
      if test -z "$1"; then
        usage
      fi
      if test -n "$SSH_CERT_TYPE"; then
        usage
      fi
      SSH_CERT_TYPE="$1"
      shift
      case $SSH_CERT_TYPE in
        client)
          SSH_X509V3_EXTENSIONS="usr_cert"
          ;;
        server)
          SSH_X509V3_EXTENSIONS="srv_cert"
          ;;
        self)
          SSH_SELFCERT=yes
          SSH_X509V3_EXTENSIONS=self_cert
          ;;
        ocsp)
          if test "x$SSH_OCSP" = "xyes"; then
            SSH_X509V3_EXTENSIONS="ocsp_cert"
          else
            echo "${warn}unsupported type${norm}" >&2
            usage
          fi
          ;;
        *)
          echo "${warn}wrong type${norm}" >&2
          usage
          ;;
      esac
      ;;

    -n|\
    -name)
      shift
      if test -z "$1"; then
        usage
      fi
      if test -n "${SSH_BASE_DN_CN}"; then
        usage
      fi
      SSH_BASE_DN_CN="$1"
      shift
      ;;

    *)
      usage
      ;;
  esac
done

test -z "${SSH_BASE_KEY}" && usage
test ! -r "${SSH_BASE_KEY}" && { error_file_not_readable; exit 1; }
test -z "${SSH_BASE_DN_CN}" && usage
test -z "${SSH_CERT_TYPE}" && usage


CA_LOG="$CWD/ca-3.$SSH_BASE_KEY.$SSH_X509V3_EXTENSIONS.log"
create_empty_file .delmy &&
update_file .delmy "$CA_LOG" > /dev/null || exit $?


# ===
cre_csr () {
  echo "=== create a new CSR ===" >> "$CA_LOG"
  (
    if test "$SSH_X509V3_EXTENSIONS" != "usr_cert"; then
      SSH_DN_EM="."
    fi

    cat <<EOF
$SSH_DN_C
$SSH_DN_ST
$SSH_DN_L
$SSH_DN_O
${SSH_DN_OU}-2
${SSH_DN_OU}-1
${SSH_DN_OU}-3
$SSH_BASE_DN_CN(${type}${subtype})
$SSH_DN_EM
.
EOF
  ) |
  $OPENSSL req \
    -new \
    -config "${SSH_CACFGFILE}" \
    $SSH_DN_UTF8_FLAG \
    -key "${SSH_BASE_KEY}" \
    -passin pass:"" \
    -out "${TMPDIR}/${SSH_X509V3_EXTENSIONS}-${type}${subtype}.csr" \
    2>> "$CA_LOG" \
  ; show_status $? "- ${extd}CSR${norm}"
}


# ===
cre_crt () {
  echo "=== create a new CRT ===" >> "$CA_LOG"
  $OPENSSL ca \
    -config "${SSH_CACFGFILE}" \
    -batch \
    -in "${TMPDIR}/${SSH_X509V3_EXTENSIONS}-${type}${subtype}.csr" \
    -name "ca_test_$type" \
    -passin pass:$KEY_PASS \
    -out "${TMPDIR}/${SSH_X509V3_EXTENSIONS}-${type}${subtype}.crt" \
    -extensions ${SSH_X509V3_EXTENSIONS} \
    2>> "$CA_LOG" \
  ; show_status $? "- ${extd}CRT${norm}" ||
  { retval=$?
    printf '%s' "${warn}"
    grep 'ERROR:' "$CA_LOG"
    printf '%s' "${norm}"
    return $retval
  }

  sync
  $OPENSSL verify \
    -CAfile "$SSH_CAROOT/$CACERTFILE" \
    "${TMPDIR}/${SSH_X509V3_EXTENSIONS}-${type}${subtype}.crt" &&
  rm -f "${TMPDIR}/${SSH_X509V3_EXTENSIONS}-${type}${subtype}.csr" ||
    return $?

  # openssl verify exit always with zero :(

  printf '%s' '- ' &&
  update_file \
    "$TMPDIR/$SSH_X509V3_EXTENSIONS-$type$subtype.crt" \
    "$SSH_BASE_KEY-$type$subtype.crt" ||
    return $?

  # openssl ca command does not support name option
  F="$SSH_BASE_KEY-$type$subtype.crt"
  mv "$F" t-"$F" &&
  $OPENSSL x509 \
    -in t-"$F" \
    -text $OPENSSL_NAMEOPT \
    > "$F" &&
  rm t-"$F"
}


# ===
cre_self () {
  echo "=== create a new self-CRT ===" >> "$CA_LOG"
  (
    cat <<EOF
$SSH_DN_C
$SSH_DN_ST
$SSH_DN_L
$SSH_DN_O
${SSH_DN_OU}-2
${SSH_DN_OU}-1
${SSH_DN_OU}-3
$SSH_BASE_DN_CN(${type}-self)
$SSH_DN_EM
.
EOF
  ) |
  $OPENSSL req \
    -new -x509 \
    -config "$SSH_CACFGFILE" \
    $SSH_DN_UTF8_FLAG \
    -key "$SSH_BASE_KEY" \
    -days $SSH_CACERTDAYS \
    -passin pass:"" \
    -out "$TMPDIR/${SSH_X509V3_EXTENSIONS}-${type}".crt \
    -extensions $SSH_X509V3_EXTENSIONS \
    2>> "$CA_LOG" \
  ; show_status $? "- ${extd}self-CRT${norm}" \
  || return $?

  update_file \
    "$TMPDIR/${SSH_X509V3_EXTENSIONS}-${type}".crt \
    "${SSH_BASE_KEY}-${type}".crt
}


# ===
cre_ssh_crt () {
  printf '%s' "- ${extd}PKIX-SSH certificate${norm}"
  ( cat "$SSH_BASE_KEY"

    $OPENSSL x509 \
     -in "$SSH_BASE_KEY-$type$subtype.crt" \
     -subject -issuer -alias $OPENSSL_NAMEOPT
  ) > "$SSH_BASE_KEY-$type$subtype" &&
  chmod 600 "$SSH_BASE_KEY-$type$subtype" \
  ; show_status $?
}


cre_ssh_pubkey () {
  printf '%s' "- ${extd}PKIX-SSH public key${norm}"
  "$TEST_SSH_SSHKEYGEN" -y -f "${SSH_BASE_KEY}-${type}${subtype}" \
    > "${SSH_BASE_KEY}-${type}${subtype}.pub" \
  ; show_status $?
}


cre_p12 () {
  P12_OPT=
  if test -n "$OPENSSL_FIPS"; then
    P12_OPT="$P12_OPT -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES"
  fi
  printf '%s' "- ${extd}PKCS #12${norm} file"
  ( cat "$SSH_BASE_KEY-$type$subtype"
    cat "$SSH_CAROOT/crt/$CAKEY_PREFIX-$type.crt.pem"
  ) | \
  $OPENSSL pkcs12 $P12_OPT \
    -passin pass: \
    -passout pass: \
    -out "$SSH_BASE_KEY-$type$subtype".p12 \
    -export \
  ; show_status $?
}


revoke_crt () {
  echo "=== revoke a CRT ===" >> "$CA_LOG"
  printf '%s' "- ${extd}revoke${norm} certificate"
  $OPENSSL ca \
    -config "${SSH_CACFGFILE}" \
    -name "ca_test_$type" \
    -passin pass:$KEY_PASS \
    -revoke "${SSH_BASE_KEY}-${type}${subtype}.crt" \
    2>> "$CA_LOG" \
  ; show_status $?
}


# ===
cre_all2 () {
  echo
  printf '%s\n' "creating ${extd}${SSH_X509V3_EXTENSIONS}${norm} for ${extd}${SSH_BASE_DN_CN}${norm}(${attn}${type}${norm}${warn}${subtype}${norm}) ..."

  if test "$SSH_SELFCERT" = "yes"; then
    cre_self
  else
    cre_csr &&
    cre_crt
  fi || return $?

  test "$SSH_X509V3_EXTENSIONS" = "ocsp_cert" && return 0

  cre_ssh_crt &&
  cre_ssh_pubkey &&
  cre_p12
}


# ===
cre_all () {
(
  subtype=
  if test "$SSH_SELFCERT" = "yes" ; then
    # NOTE self-issued use name in format "selfid_${keytype}"
    keytype=`echo $SSH_BASE_KEY | sed 's/^selfid_//'`
    if test "$SSH_BASE_KEY" = "$keytype" ; then
      echo "For self-issued ${warn}cannot obtain keytype from keyname - ${attn}$SSH_BASE_KEY${norm}" >&2
      exit 1
    fi
    type=$keytype
    cre_all2 || exit $?
  else
    for type in $SSH_SIGN_TYPES ; do
      cre_all2 || exit $?
    done
  fi

  if test "$SSH_X509V3_EXTENSIONS" = "srv_cert" || \
     test "$SSH_SELFCERT" = "yes" \
  ; then
    create_empty_file $SSH_BASE_KEY.certstamp
    exit $?
  fi

  subtype="-revoked"
  for type in ${SSH_SIGN_TYPES}; do
    cre_all2 &&
    revoke_crt || exit $?
  done

  create_empty_file $SSH_BASE_KEY.certstamp
)
}

# ===

cre_all; retval=$?

echo
show_status $retval "${extd}Creating${norm} ${attn}${SSH_BASE_DN_CN}${norm} group of ${warn}test${norm} certificates"
