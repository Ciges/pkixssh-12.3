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
# DESCRIPTION: Create "Test Certificate Authority" CRLs.
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/4-cre_crls.sh$//'`
. "${SCRIPTDIR}shell.rc"
. "${SCRIPTDIR}functions"
. "${SCRIPTDIR}config"


CA_LOG="$CWD/ca-4.log"
create_empty_file .delmy &&
update_file .delmy "$CA_LOG" > /dev/null || exit $?


# ===
cre_crlfile() {
(
  type="$1"

  cd "$SSH_CAROOT/crl" || exit $?

  FILE="${CAKEY_PREFIX}-${type}.crl.pem"

  printf '%s' "- ${attn}${type}${norm} certificates"
  ${OPENSSL} ca \
    -config "${SSH_CACFGFILE}" \
    -name "ca_test_$type" \
    -passin pass:${KEY_PASS} \
    -gencrl \
    -out "${FILE}" \
    2>> "$CA_LOG" \
  ; show_status $? || exit $?

  cre_crl_hash_link "$FILE"
)
}


# ===
cre_crlindir () {
  echo "=== create a new CRL ===" >> "$CA_LOG"
  rm -f "$SSH_CAROOT/crl"/* 2>/dev/null

  printf '%s\n' "creating ${extd}CA CRL file${norm} for ..."
  for type in ${SSH_SIGN_TYPES}; do
    cre_crlfile "${type}" || return $?
  done

  return 0
}


# ===
cre_CAcrlfile () {
(
  crlfile="$SSH_CAROOT/$CACRLFILE"

  # NOTE -nameopt is without effect over -text
  # As work-around file will contain in addition
  # issuer name.

  create_empty_file "$crlfile"-t &&
  for type in $SSH_SIGN_TYPES; do
    (
      if test -n "$OPENSSL_NAMEOPT"; then
        $OPENSSL crl $OPENSSL_NAMEOPT \
        -in "$SSH_CAROOT/crl/$CAKEY_PREFIX-$type.crl.pem" \
        -issuer -noout \
        2>> "$CA_LOG" &&
        echo "============================================================"
      fi &&
      $OPENSSL crl \
      -in "$SSH_CAROOT/crl/$CAKEY_PREFIX-$type.crl.pem" \
      -text \
      2>> "$CA_LOG" \
      && echo && echo
    ) >> "$crlfile"-t || exit $?
  done

  mv "$crlfile"-t "$crlfile"
)
}


# ===
cre_all () {
  cre_crlindir || return $?

  printf '%s' "creating ${extd}CA CRL ${attn}common${norm} ${extd}file${norm} ..."
  cre_CAcrlfile; show_status $?
}


# ===
cre_all; retval=$?

show_status $retval "${extd}Creating${norm} ${warn}TEST${norm} ${attn}Certificate Authority${norm} CRL files"
