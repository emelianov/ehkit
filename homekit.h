// HomeKit Core

#pragma once

extern "C" {
  #include "tlv.h"
}
#include "srpImpl.h"
#include "tools.h"

extern char bufferUrl[256];
extern uint8_t raw[4096];
extern int rawSize;

typedef enum tlvCode {
    
    // States
    kTLVState_M0             = 0x00,  // Custom. Reserved by spec
    kTLVState_M1             = 0x01,
    kTLVState_M2             = 0x02,
    kTLVState_M3             = 0x03,
    kTLVState_M4             = 0x04,
    kTLVState_M5             = 0x05,
    kTLVState_M6             = 0x06,
    
    // Methods Table 4-4
    kTLVMethod_Reserved     = 0x00,
    kTLVMethod_PairSetup    = 0x01,
    kTLVMethod_PairVerify   = 0x02,
    kTLVMethod_AddPairing   = 0x03,
    kTLVMethod_RemovePairing = 0x04,
    kTLVMethod_ListPairings = 0x05,
    
    // TLV Values Table 4-6
    kTLVType_Method        = 0x00,
    kTLVType_Identifier    = 0x01,
    kTLVType_Salt          = 0x02,
    kTLVType_PublicKey     = 0x03,
    kTLVType_Proof         = 0x04,
    kTLVType_EncryptedData = 0x05,
    kTLVType_State         = 0x06,
    kTLVType_Error         = 0x07,
    kTLVType_RetryDelay    = 0x08,
    kTLVType_Certificate   = 0x09,
    kTLVType_Signature     = 0x0A,
    kTLVType_Permissions   = 0x0B,
    kTLVType_FragmentData  = 0x0C,
    kTLVType_FragmentLast  = 0x0D,
    kTLVType_Separator     = 0xFF,


    // Error Codes Table 4-5
    kTLVError_Success             = 0x00,  // Custom. Reserved by spec
    kTLVError_Unknown             = 0x01,
    kTLVError_Authentication      = 0x02,
    kTLVError_Backoff             = 0x03,
    kTLVError_MaxPeers            = 0x04,
    kTLVError_MaxTries            = 0x05,
    kTLVError_Unavailable         = 0x06,
    kTLVError_Busy                = 0x07
    
} tlvCode_t;

bool paired = false;
tlvCode_t pairingState = kTLVState_M0;
uint16_t pairingAttempt = 0;
#define PAIRINGS_MAX 100

void pairing() {
  tlv_values_t* tlvData = tlv_new();
  tlv_values_t* tlvResponse = tlv_new();

  tlv_parse(raw, rawSize, tlvData);
  if (tlv_get_integer_value(tlvData, kTLVType_Method, 0) != kTLVMethod_PairSetup) { // Unexpected method
    tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unknown);
    goto format;
  }
  espWatchdogDisable();
  espOverclock();
  switch (tlv_get_integer_value(tlvData, kTLVType_State, 0)) {
    case kTLVState_M1:
      if (paired) { // Already paired
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unavailable);
        break;
      }
      if (pairingState != kTLVState_M0) { // Pairing already in progress
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Busy);
        break;
      }
      if (pairingAttempt > PAIRINGS_MAX) { // Too many pairing attempts
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_MaxTries);
        break;
      }
      tlv_add_integer_value(tlvResponse, kTLVType_State, kTLVState_M2);
      tlv_add_value(tlvResponse, kTLVType_PublicKey, public_key, public_key_size);
      tlv_add_value(tlvResponse, kTLVType_Salt, salt, salt_size);
      pairingState = kTLVState_M2;
    break;
    case kTLVState_M3: {
      if (pairingState != kTLVState_M2) { // Unexpected state
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unknown);
        break;
      }
      tlv_t* ios_public_key = tlv_get_value(tlvData, kTLVType_PublicKey);
      tlv_t* proof = tlv_get_value(tlvData, kTLVType_Proof);
      if (!ios_public_key || !proof) {
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
      }
      if (int r = crypto_srp_compute_key(srp, ios_public_key->value, ios_public_key->size, public_key, public_key_size)) {
        Serial.printf("SRP: Failed to compute SRP shared secret (code %d)", r);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
      }
      free(public_key);
      public_key = NULL;
      public_key_size = 0;
      if (int r = crypto_srp_verify(srp, proof->value, proof->size)) {
        Serial.printf("SRP: Failed to verify peer's proof (code %d)", r);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
      }
      size_t server_proof_size = 0;
      crypto_srp_get_proof(srp, NULL, &server_proof_size);
      uint8_t *server_proof = (uint8_t*)malloc(server_proof_size);
      crypto_srp_get_proof(srp, server_proof, &server_proof_size);
      tlv_add_integer_value(tlvResponse, kTLVType_State, kTLVState_M4);
      tlv_add_value(tlvResponse, kTLVType_Proof, server_proof, server_proof_size);
      free(server_proof);
      pairingState = kTLVState_M4;
    }
    break;
    case kTLVState_M5: {
      if (pairingState != kTLVState_M4) { // Unexpected state
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unknown);
        break;
      }
      byte shared_secret[HKDF_HASH_SIZE];
      size_t shared_secret_size = sizeof(shared_secret);
      const char salt1[] = "Pair-Setup-Encrypt-Salt";
      const char info1[] = "Pair-Setup-Encrypt-Info";
      if (int r = crypto_srp_hkdf(srp, (const unsigned char*)salt1, sizeof(salt1)-1, (byte *)info1, sizeof(info1)-1, shared_secret, &shared_secret_size)) {
        Serial.printf("SRP: Failed to generate shared secret (code %d)", r);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
      }

       tlv_t *tlv_encrypted_data = tlv_get_value(tlvData, kTLVType_EncryptedData);
       if (!tlv_encrypted_data) {
         Serial.printf("Invalid payload: no encrypted data");
         tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
         break;
       }

       size_t decrypted_data_size = 0;
       crypto_chacha20poly1305_decrypt(shared_secret, (byte *)"\x0\x0\x0\x0PS-Msg05", NULL, 0, tlv_encrypted_data->value, tlv_encrypted_data->size, NULL, &decrypted_data_size);
       uint8_t* decrypted_data = (uint8_t*)malloc(decrypted_data_size);
            // TODO: check malloc result
       if (int r = crypto_chacha20poly1305_decrypt(shared_secret, (byte *)"\x0\x0\x0\x0PS-Msg05", NULL, 0, tlv_encrypted_data->value, tlv_encrypted_data->size, decrypted_data, &decrypted_data_size)) {
         Serial.printf("Failed to decrypt data (code %d)", r);
         free(decrypted_data);
          tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
          break;
       }

       tlv_values_t *decrypted_message = tlv_new();
       if (int r = tlv_parse(decrypted_data, decrypted_data_size, decrypted_message)) {
        Serial.printf("Failed to parse decrypted TLV (code %d)", r);
        tlv_free(decrypted_message);
        free(decrypted_data);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
       }
       free(decrypted_data);

       tlv_t *tlv_device_id = tlv_get_value(decrypted_message, kTLVType_Identifier);
       if (!tlv_device_id) {
        Serial.println("Invalid encrypted payload: no device identifier");
        tlv_free(decrypted_message);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
       }

       tlv_t *tlv_device_public_key = tlv_get_value(decrypted_message, kTLVType_PublicKey);
       if (!tlv_device_public_key) {
        Serial.println("Invalid encrypted payload: no device public key");
        tlv_free(decrypted_message);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
       }

       tlv_t *tlv_device_signature = tlv_get_value(decrypted_message, kTLVType_Signature);
       if (!tlv_device_signature) {
        Serial.println("Invalid encrypted payload: no device signature");
        tlv_free(decrypted_message);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
       }


       ed25519_key *device_key = crypto_ed25519_new();
       if (int r = crypto_ed25519_import_public_key(device_key, tlv_device_public_key->value, tlv_device_public_key->size)) {
        Serial.printf("ED25519: Failed to import device public Key (code %d)", r);
        crypto_ed25519_free(device_key);
        tlv_free(decrypted_message);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
       }

       byte device_x[HKDF_HASH_SIZE];
       size_t device_x_size = sizeof(device_x);
       const char salt2[] = "Pair-Setup-Controller-Sign-Salt";
       const char info2[] = "Pair-Setup-Controller-Sign-Info";
       if (int r = crypto_srp_hkdf(srp, (byte *)salt2, sizeof(salt2)-1, (byte *)info2, sizeof(info2)-1, device_x, &device_x_size)) {
        Serial.printf("SRP: Failed to generate DeviceX (code %d)", r);
        crypto_ed25519_free(device_key);
        tlv_free(decrypted_message);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
       }

       size_t device_info_size = device_x_size + tlv_device_id->size + tlv_device_public_key->size;
       uint8_t* device_info = (uint8_t*)malloc(device_info_size);
       memcpy(device_info, device_x, device_x_size);
       memcpy(device_info + device_x_size, tlv_device_id->value, tlv_device_id->size);
       memcpy(device_info + device_x_size + tlv_device_id->size, tlv_device_public_key->value, tlv_device_public_key->size);
       if (int r = crypto_ed25519_verify(device_key, device_info, device_info_size, tlv_device_signature->value, tlv_device_signature->size)) {
        Serial.printf("ED25519: Failed to generate DeviceX (code %d)", r);
        free(device_info);
        crypto_ed25519_free(device_key);
        tlv_free(decrypted_message);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
       }
       free(device_info);

       char *device_id = strndup((const char *)tlv_device_id->value, tlv_device_id->size);
       uint8_t pairing_permissions_admin = 1;
//       if (int r = homekit_storage_add_pairing(device_id, device_key, pairing_permissions_admin)) {
//        Serial.printf("HOMEKIT: Failed to store pairing (code %d)", r);
//        free(device_id);
//        crypto_ed25519_free(device_key);
//        tlv_free(decrypted_message);
//        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
//        break;
//       }

       free(device_id);
       crypto_ed25519_free(device_key);
       tlv_free(decrypted_message);




      size_t accessory_public_key_size = 0;
      crypto_ed25519_export_public_key(accessory_key, NULL, &accessory_public_key_size);
      uint8_t* accessory_public_key = (uint8_t*)malloc(accessory_public_key_size);
      if (int r = crypto_ed25519_export_public_key(accessory_key, accessory_public_key, &accessory_public_key_size)) {
        Serial.printf("Failed to export accessory public key (code %d)", r);
        free(accessory_public_key);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
       }
       size_t accessory_id_size = strlen(accessory_id);
       size_t accessory_info_size = HKDF_HASH_SIZE + accessory_id_size + accessory_public_key_size;
       uint8_t* accessory_info = (uint8_t*)malloc(accessory_info_size);
       size_t accessory_x_size = accessory_info_size;
       const char salt3[] = "Pair-Setup-Accessory-Sign-Salt";
       const char info3[] = "Pair-Setup-Accessory-Sign-Info";
       if (int r = crypto_srp_hkdf(srp, (byte *)salt3, sizeof(salt3)-1, (byte *)info3, sizeof(info3)-1, accessory_info, &accessory_x_size)) {
        Serial.printf("Failed to generate AccessoryX (code %d)", r);
        free(accessory_info);
        free(accessory_public_key);
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
       }
       memcpy(accessory_info + accessory_x_size, accessory_id, accessory_id_size);
       memcpy(accessory_info + accessory_x_size + accessory_id_size, accessory_public_key, accessory_public_key_size);

        size_t accessory_signature_size = 0;
        crypto_ed25519_sign(accessory_key, accessory_info, accessory_info_size, NULL, &accessory_signature_size);
        uint8_t* accessory_signature = (uint8_t*)malloc(accessory_signature_size);
        if (int r = crypto_ed25519_sign(accessory_key, accessory_info, accessory_info_size, accessory_signature, &accessory_signature_size)) {
          Serial.printf("Failed to generate accessory signature (code %d)", r);
          free(accessory_signature);
          free(accessory_public_key);
          free(accessory_info);
          tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
          break;
        }

        free(accessory_info);

        tlv_values_t *response_message = tlv_new();
        tlv_add_value(response_message, kTLVType_Identifier, (byte*)accessory_id, accessory_id_size);
        tlv_add_value(response_message, kTLVType_PublicKey, accessory_public_key, accessory_public_key_size);
        tlv_add_value(response_message, kTLVType_Signature, accessory_signature, accessory_signature_size);

        free(accessory_public_key);
        free(accessory_signature);

        size_t response_data_size = 0;
        tlv_format(response_message, NULL, &response_data_size);
        uint8_t* response_data = (uint8_t*)malloc(response_data_size);
        if (int r = tlv_format(response_message, response_data, &response_data_size)) {
          Serial.printf("Failed to format TLV response (code %d)", r);
          free(response_data);
          tlv_free(response_message);
          tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
          break;
        }
        tlv_free(response_message);

        size_t encrypted_response_data_size = 0;
        crypto_chacha20poly1305_encrypt(shared_secret, (byte *)"\x0\x0\x0\x0PS-Msg06", NULL, 0, response_data, response_data_size, NULL, &encrypted_response_data_size);
        uint8_t* encrypted_response_data = (uint8_t*)malloc(encrypted_response_data_size);
        if (int r = crypto_chacha20poly1305_encrypt(shared_secret, (byte *)"\x0\x0\x0\x0PS-Msg06", NULL, 0, response_data, response_data_size, encrypted_response_data, &encrypted_response_data_size)) {
          Serial.printf("Failed to encrypt response data (code %d)", r);
          free(response_data);
          free(encrypted_response_data);
          tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
          break;
        }
        free(response_data);
        tlv_values_t *response = tlv_new();
        tlv_add_integer_value(response, kTLVType_State, kTLVState_M6);
        tlv_add_value(response, kTLVType_EncryptedData, encrypted_response_data, encrypted_response_data_size);
        free(encrypted_response_data);

    }
    break;
    default:
      tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unknown);
  }
  espWatchdogEnable();
  yield();
  format:
  tlv_format(tlvResponse, (unsigned char*)&response, &responseLen);
  tlv_free(tlvData);
  tlv_free(tlvResponse);
}

