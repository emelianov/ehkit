#pragma once


extern uint8_t response[4096];
extern size_t responseLen;

extern "C" {
  #include "crypto.h"

}
#include <wolfssl.h>
#include "helpers.h"

const char *username = "Pair-Setup";
const char *password = "123-00-321";

Srp* srp;
size_t public_key_size = 0;
uint8_t* public_key;
size_t salt_size = 0;
uint8_t *salt;

char* accessory_id;
ed25519_key* accessory_key;

uint32_t srpInit() {
  srp = crypto_srp_new();
  crypto_srp_init(srp, username, password);
  crypto_srp_get_public_key(srp, NULL, &public_key_size);
  public_key = (uint8_t*)malloc(public_key_size);
  if (!public_key) {
    Serial.println("SRP: Memory allocation error");
    return 0;
  }
  if (int r = crypto_srp_get_public_key(srp, public_key, &public_key_size)) {
    Serial.printf("SRP: Failed to dump public key (code %d)", r);
    free(public_key);
    return 0;
  }
  crypto_srp_get_salt(srp, NULL, &salt_size);
  salt = (uint8_t*)malloc(salt_size);
  if (int r = crypto_srp_get_salt(srp, salt, &salt_size)) {
    Serial.printf("SRP: Failed to get salt (code %d)", r);
    free(salt);
    free(public_key);
    return 0;
  }
  Serial.println("SRP: Init done");
  accessory_id = homekit_accessory_id_generate();
  accessory_key = crypto_ed25519_generate();

  return 0;
}

