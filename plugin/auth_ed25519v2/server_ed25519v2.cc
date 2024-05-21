/*
   Copyright (c) 2024, MariaDB Corporation.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1335  USA */

#include <mysql/plugin_auth.h>
#include <mysql/plugin.h>
#include <mysqld_error.h>
#include "my_global.h"
#include "my_rnd.h"
#include "mysql/service_base64.h"
#include "ed25519v2_common.h"
#include "scope.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <cstring>


bool compute_derived_key(const char* password, size_t pass_len,
                         const Server_challenge *params, uchar *derived_key)
{
  DBUG_ASSERT(params->hash == 'P');
  int ret = PKCS5_PBKDF2_HMAC(password, (int)pass_len, params->salt,
                              CHALLENGE_SALT_LENGTH,
                              1 << (params->iterations + 10),
                              EVP_sha512(),
                              PBKDF2_HASH_LENGTH, derived_key);
  if(ret == 0)
    ERR_print_errors_fp(stderr);
  return ret;
}


bool verify_ed25519(const uchar *public_key, const uchar *signature,
                    const uchar *message, size_t message_len)
{
  EVP_MD_CTX *mdctx= EVP_MD_CTX_new();
  EVP_PKEY *pkey= EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                              public_key, 32);
  SCOPE_EXIT([mdctx, pkey](){
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
  });

  int ret= 0;
  if (pkey && mdctx &&
      EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) &&
      (ret= EVP_DigestVerify(mdctx, signature, ED25519_SIG_LENGTH,
                             message, message_len)) == 1)
    return true;

  if (ret != 0)
    ERR_print_errors_fp(stderr);

  return false;
}


void generate_random_bytes(uchar *buf, size_t len)
{
  struct my_rnd_struct rnd_state;
  my_rnd_init(&rnd_state, 1234, 567);

  for (size_t i = 0; i < len; ++i)
    buf[i]= (uchar)(my_rnd(&rnd_state) * 256.0);
}


constexpr size_t base64_length_simple(size_t input_length)
{
  return ((input_length + 2) / 3) * 4;
}


constexpr size_t base64_length(size_t len)
{
  return base64_length_simple(len) + (base64_length_simple(len) - 1U) / 76;
}


struct alignas(1) Passwd_as_stored
{
  char algorithm;
  uint8 iterations;
  char colon;
  char salt[base64_length(CHALLENGE_SALT_LENGTH)];
  char colon2;
  char pub_key[base64_length(ED25519_KEY_LENGTH)];
};


Server_challenge passwd_to_challenge(const Passwd_as_stored *stored_password)
{
  union
  {
    Server_challenge challenge;
    uchar buff[sizeof challenge + 1]; // fix my_base64_decode adds \0 in the end
  };
  challenge.hash= stored_password->algorithm; // 'P'
  challenge.iterations= stored_password->iterations - '0';

  my_base64_decode(stored_password->salt, base64_length(CHALLENGE_SALT_LENGTH),
                   challenge.salt, NULL, 0);
  return challenge;
}

bool verify_passwd(const Passwd_as_stored *passwd)
{
  bool result= passwd->algorithm == 'P';
  result= result && (passwd->iterations >= '0' && passwd->iterations <= '3');
  result= result && (passwd->colon == ':');
  result= result && (passwd->colon2 == ':');

  return result;
}


bool ed25519_derive_public_key(const unsigned char *raw_private_key, unsigned char *pub_key) {
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                raw_private_key,
                                                ED25519_KEY_LENGTH);
  bool res= pkey != NULL;
  size_t len= ED25519_KEY_LENGTH;
  if (pkey)
    res= EVP_PKEY_get_raw_public_key(pkey, pub_key, &len); // 1 == success

  if (!res)
    ERR_print_errors_fp(stderr);

  EVP_PKEY_free(pkey);
  return res;
}


int hash_password(const char *password, size_t password_length,
                  char *hash, size_t *hash_length)
{
  Server_challenge params;
  params.iterations= 0;
  params.hash= 'P';
  generate_random_bytes(params.salt, CHALLENGE_SALT_LENGTH);

  uchar derived_key[PBKDF2_HASH_LENGTH];
  if (!compute_derived_key(password, password_length, &params, derived_key))
    return 1;

  unsigned char public_key[ED25519_KEY_LENGTH];
  if (!ed25519_derive_public_key(derived_key, public_key))
    return 1;

  Passwd_as_stored *passwd= (Passwd_as_stored*)hash;
  passwd->algorithm= 'P';
  passwd->iterations= '0';
  my_base64_encode(params.salt, CHALLENGE_SALT_LENGTH, passwd->salt);
  my_base64_encode(public_key, CHALLENGE_SALT_LENGTH, passwd->pub_key);
  passwd->colon= passwd->colon2= ':';

  *hash_length = sizeof *passwd;

  return 0;
}


int digest_to_binary(const char *hash, size_t hash_length,
                    unsigned char *out, size_t *out_length)
{
  if (hash_length != sizeof (Passwd_as_stored))
    return 1;
  if (!verify_passwd((Passwd_as_stored*)hash))
    return 1;

  memcpy(out, hash, hash_length);
  *out_length = hash_length;

  return 0;
}


void mpvio_init_auth_info(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *ai);

int auth(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  union alignas (1)
  {
    struct
    {
      uchar server_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      uchar client_scramble[CHALLENGE_SCRAMBLE_LENGTH];
    };
    uchar scramble_pair[1];
  };

  generate_random_bytes(server_scramble, CHALLENGE_SCRAMBLE_LENGTH);

  if (vio->write_packet(vio, server_scramble, CHALLENGE_SCRAMBLE_LENGTH))
    return CR_ERROR;

  mpvio_init_auth_info(vio, info);

  Passwd_as_stored* passwd= (Passwd_as_stored*)info->auth_string;

  Server_challenge challenge= passwd_to_challenge(passwd);

  if (vio->write_packet(vio, challenge.start, sizeof (Server_challenge)))
    return CR_ERROR;

  Client_signed_response *client_response;
  int bytes_read= vio->read_packet(vio, (uchar**)&client_response);
  if (bytes_read < 0)
    return CR_ERROR;
  if (bytes_read != sizeof *client_response)
    return CR_AUTH_HANDSHAKE;

  uchar pub_key[ED25519_KEY_LENGTH + 1];
  my_base64_decode(passwd->pub_key, base64_length(ED25519_KEY_LENGTH), pub_key,
                   NULL, 0);
  memcpy(client_scramble, client_response->client_scramble,
         CHALLENGE_SCRAMBLE_LENGTH);

  if (!verify_ed25519(pub_key, client_response->signature,
                      scramble_pair, CHALLENGE_SCRAMBLE_LENGTH * 2))
    return CR_AUTH_HANDSHAKE;

  return CR_OK;
}

static struct st_mysql_auth info =
{
  MYSQL_AUTHENTICATION_INTERFACE_VERSION,
  "client_ed25519v2",
  auth,
  hash_password,
  digest_to_binary
};


maria_declare_plugin(ed25519v2)
{
  MYSQL_AUTHENTICATION_PLUGIN,
  &info,
  "ed25519v2",
  "Nikita Maliavin",
  "ED25519 v2 - asymmetric challenge-based authentication",
  PLUGIN_LICENSE_GPL,
  NULL,
  NULL,
  0x2,
  NULL,
  NULL,
  "2",
  MariaDB_PLUGIN_MATURITY_BETA
}
maria_declare_plugin_end;
