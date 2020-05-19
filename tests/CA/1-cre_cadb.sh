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
# DESCRIPTION: Create a new certificate authority config and database.
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/1-cre_cadb.sh$//'`
. "${SCRIPTDIR}shell.rc"
. "${SCRIPTDIR}functions"
. "${SCRIPTDIR}config"

if test yes = "$SSH_DN_FORCE_UTF8"; then
  string_mask=utf8only
else
  string_mask=default
fi

# ===
# args:
#   $1 - type
#   $2 - policy section
echo_CA_section_start () {
  printf '\n\n[ ca_test_%s ]\n' "$1"
cat <<EOF
certs           = \$dir/crt             # Where the issued certs are kept
crl_dir         = \$dir/crl             # Where the issued crl are kept
# database index file:
database        = \$dir/index-$1.txt
new_certs_dir   = \$dir/newcerts        # default place for new certs.
serial          = \$dir/serial          # The current serial number

#x509_extensions = usr_cert            # The default extensions to add to the cert
# how long to certify for:
default_days    = $SSH_CACERTDAYS
# how long before next CRL:
default_crl_days= $SSH_CACRLDAYS
policy          = $2

# print options (internal use)
#name_opt        = oneline,-space_eq,-esc_msb # print UTF-8
#name_opt        = utf8,sep_comma_plus
cert_opt        = compatible

EOF
}


# ===
# args:
#   $1 - CA level
#   $2 - policy section
#   $3 - digest
#   $4 - key sub-string
#   $5 - cert sub-string
echo_CA_section () {
(
  echo_CA_section_start "$1" "$2"
cat << EOF
# which md to use:
default_md      = $3

# The private key (!)
private_key     = \$dir/keys/$CAKEY_PREFIX-$4.key

#The CA certificate (!)
certificate     = \$dir/crt/$CAKEY_PREFIX-$5.crt.pem
EOF
)
}


# ===
# args:
#   none
echo_CA_ocsp_options () {
if test "x$SSH_OCSP" = "xyes"; then
cat << EOF

# OCSP Validator(Responder) URI
# Since OpenSSL OCSP responder support only one issuer certificate
# we should setup for the test cases many responders - each certificate
# type with responder on different port.
EOF
  printf "authorityInfoAccess = "
(
  port=`expr $SSH_VA_BASEPORT - 1`
  for DIGEST in $RSA_DIGEST_LIST ; do
    port=`expr $port + 1`
    if test $port -eq $SSH_VA_BASEPORT ; then
      printf "OCSP;URI:http://$SSHD_LISTENADDRESS:$port"
    else
      printf ",OCSP;URI:http://$SSHD_LISTENADDRESS:$port"
    fi
  done
  if expr "$SSH_CAKEY_TYPES" : .*dsa > /dev/null ; then
    port=`expr $port + 1`
    printf ",OCSP;URI:http://$SSHD_LISTENADDRESS:$port"
  fi
  if expr "$SSH_CAKEY_TYPES" : .*ed25519 > /dev/null ; then
    port=`expr $port + 1`
    printf ",OCSP;URI:http://$SSHD_LISTENADDRESS:$port"
  fi
  if expr "$SSH_CAKEY_TYPES" : .*ed448 > /dev/null ; then
    port=`expr $port + 1`
    printf ",OCSP;URI:http://$SSHD_LISTENADDRESS:$port"
  fi
)
  printf "\n"
fi
}


# ===
cre_config () {
cat << EOF > "$1"
# Where everything is kept:
dir = $SSH_CAROOT

[ ca ]
#md5 is not allowed in FIPSmode
#default_ca              = ca_test_rsa_md5
default_ca              = ca_test_rsa_sha1


# For the CA policy
[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ ca_policy_match ]
countryName             = match
stateOrProvinceName     = match
localityName            = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional


[ req ]
default_bits            = 1024
distinguished_name      = req_distinguished_name
attributes              = req_attributes
#prompt                  = no
#string_mask             = MASK: <unsigned long> | nombstr | pkix | utf8only | default(=0xFFFFFFFFL)
string_mask             = $string_mask
#utf8                    = yes

# The extensions to add to a certificate request:
#???req_extensions          = usr_cert


[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = $SSH_DN_C
countryName_min                 = 2
countryName_max                 = 2

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = $SSH_DN_ST

localityName                    = Locality Name (eg, city)
localityName_default            = $SSH_DN_L

0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = $SSH_DN_O

0.organizationalUnitName          = Organizational Unit1 Name (eg, section1 - optional)
0.organizationalUnitName_default  = ${SSH_DN_OU}-1

1.organizationalUnitName          = Organizational Unit2 Name (eg, section2 - optional)
1.organizationalUnitName_default  = ${SSH_DN_OU}-2

2.organizationalUnitName          = Organizational Unit3 Name (eg, section3 - optional)
2.organizationalUnitName_default  = ${SSH_DN_OU}-3

commonName                      = Common Name (eg, YOUR name)
commonName_min                  = 2
commonName_max                  = 64

emailAddress                    = Email Address (optional)
emailAddress_max                = 40
emailAddress_default            = $SSH_DN_EM


[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20


[ ca_root_cert ]
# PKIX recommendation.

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.

# As we generate test CA we could comment next line.
basicConstraints=CA:true

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated Test CA Root Certificate"

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# Since we verify CRL signatures cRLSign must present
keyUsage = keyCertSign, cRLSign

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid:always,issuer:always


[ ca_cert ]
# PKIX recommendation.

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.

# As we generate test CA we could comment next line.
basicConstraints=CA:true

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated Test CA Certificate"

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# Since we verify CRL signatures cRLSign must present
keyUsage = keyCertSign, cRLSign

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid:always,issuer:always

# To test CRL presence this extension should exist
crlDistributionPoints = URI:attribute_only_exist
EOF


# X.509 extensions: SSH client certificates
cat << EOF >> "$1"


[ usr_cert ]
# These extensions are added when 'ca' signs a request.
basicConstraints                = CA:false
nsCertType                      = client, email

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated Test Client Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer:always
EOF

echo_CA_ocsp_options >> "$1"


# X.509 extensions: SSH server certificates
cat << EOF >> "$1"


[ srv_cert ]
# These extensions are added when 'ca' signs a request.
basicConstraints                = CA:false

# To test hostbased authentication we need
# following certificate purposes:
nsCertType                      = server,client
# Normal for server certificate is:
#nsCertType                      = server
# but in last case me must disable check of certificate purposes
# in sshd_config otherwise hostbased fail.

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated Test Server Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer:always

# Some SSH clients require server certificate to contain
# correct alternate name of type DNS (FQDN)
subjectAltName = DNS:localhost
EOF

echo_CA_ocsp_options >> "$1"


# X.509 extensions: SSH self-signed certificates
cat << EOF >> "$1"


[ self_cert ]
# These extensions are added when 'ca' signs a request.
basicConstraints                = CA:false
nsCertType                      = client, email

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated Test Client Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer:always
EOF

echo_CA_ocsp_options >> "$1"


# X.509 extensions: OCSP Validator certificates
if test "x$SSH_OCSP" = "xyes"; then
cat << EOF >> "$1"


[ ocsp_cert ]
# These extensions are added when 'ca' signs a request.
basicConstraints                = CA:false

# Normal for validator certificate is:
nsCertType                      = objsign

# This is typical in keyUsage for a validator certificate.
keyUsage = nonRepudiation, digitalSignature

# This should present for a validator certificate.
extendedKeyUsage = OCSPSigning

# This will be displayed in Netscape's comment listbox.
nsComment = "OpenSSL Generated Test OCSP Responder Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer:always
EOF
fi


echo_CA_section root ca_policy_match sha1 root0 root0 >> "$1"

for DIGEST in $RSA_DIGEST_LIST ; do
  echo_CA_section rsa_$DIGEST policy_match $DIGEST rsa rsa_$DIGEST >> "$1"
done

if expr "$SSH_CAKEY_TYPES" : .*dsa > /dev/null ; then
  echo_CA_section dsa policy_match sha1 dsa dsa >> "$1"
fi

if expr "$SSH_CAKEY_TYPES" : .*ed25519 > /dev/null ; then
  echo_CA_section ed25519 policy_match null ed25519 ed25519 >> "$1"
fi

if expr "$SSH_CAKEY_TYPES" : .*ed448 > /dev/null ; then
  echo_CA_section ed448 policy_match null ed448 ed448 >> "$1"
fi
}


# ===
cre_db () {
(
  var="${SSH_CAROOT}"

  if test ! -d "$var"; then
    mkdir -p "$var" || exit $?
  else
    count=`getNextDirName "${var}"` || exit $?
    if test -d "${var}"; then
      printf '%s' "saving old directory as ${attn}${var}.${warn}${count}${norm} ... "
      mv "${var}" "${var}.${count}"; show_status $? || exit $?
    fi
  fi

  mkdir -p "$var" &&
  mkdir "$var/crt" &&
  mkdir "$var/crl" ||
  exit $?

  create_empty_file "$var/index-root.txt" || exit $?

  for type in ${SSH_SIGN_TYPES}; do
    create_empty_file "$var/index-${type}.txt" || exit $?
  done

  mkdir "$var/newcerts" &&
  echo '200402160906000001' > "$var/serial"
)
}


# ===

cre_config "${TMPDIR}/${CACONFIG}" &&
cre_db &&
update_file "${TMPDIR}/${CACONFIG}" "${SSH_CACFGFILE}"; retval=$?

show_status $retval "${extd}Creating${norm} ${warn}TEST${norm} ${attn}Certificate Authority Database${norm}"
