// HomeKit Core

#pragma once

extern "C" {
  #include "tlv.h"
  #include "rfc6234-master/hkdf.h"
}
#include "srpImpl.h"

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
  tlv_t* PK = nullptr;
  tlv_t* proof = nullptr;

  tlv_parse(raw, rawSize, tlvData);
  if (tlv_get_integer_value(tlvData, kTLVType_Method, 0) != kTLVMethod_PairSetup) { // Unexpected method
    tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unknown);
    goto format;
  }
  switch (tlv_get_integer_value(tlvData, kTLVType_State, 0)) {
    kTLVState_M1:
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
      tlv_add_value(tlvResponse, kTLVType_PublicKey, bytes_A, len_A);
      tlv_add_value(tlvResponse, kTLVType_Salt, bytes_s, len_s);
      pairingState = kTLVState_M2;
    break;
    kTLVState_M3:
      if (pairingState != kTLVState_M2) { // Unexpected state
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unknown);
        break;
      }
      PK = tlv_get_value(tlvData, kTLVType_PublicKey);
      proof = tlv_get_value(tlvData, kTLVType_Proof);
      if (!PK || !proof) {
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
      }
      bytes_B = (unsigned char*)malloc(PK->size);
      if (!bytes_B) { // Memory allocation error
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unknown);
        break;        
      }
      memcpy(bytes_B, PK->value, PK->size);
      len_B = PK->size;
      srp_user_process_challenge(usr, (unsigned char *)srp_5054_salt, len_s, bytes_B, len_B, &bytes_M, &len_M);
      if (!bytes_M) {
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Authentication);
        break;
      }
      tlv_add_integer_value(tlvResponse, kTLVType_State, kTLVState_M4);
      tlv_add_value(tlvResponse, kTLVType_Proof, bytes_M, len_M);
      pairingState = kTLVState_M4;      
    break;
    kTLVState_M5:
      if (pairingState != kTLVState_M4) { // Unexpected state
        tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unknown);
        break;
      }
      const char salt[] = "Pair-Setup-Encrypt-Salt";
      const char info[] = "Pair-Setup-Encrypt-Info";
      int i = hkdf((const unsigned char*)bytes_s, len_s, bytes_v, len_v, (const unsigned char*)info, strlen(info), srp_user_get_session_key(usr, nullptr), 32);

      //tlvEncrypted = tlv_get_value(tlvData, kTLVType_EncryptedData);
      //tlvDecrypted
      //iOSDevicePairingID = tlv_get_value(tlvDecrypted, kTLVType_Identifier);
      //iOSDeviceLTPK = tlv_get_value(tlvDecrypted, kTLVType_PublicKey);
      //iOSDeviceSignature = tlv_get_value(tlvDecrypted, kTLVType_Signature);

    break;
    default:
    tlv_add_integer_value(tlvResponse, kTLVType_Error, kTLVError_Unknown);
  }
  format:
  tlv_format(tlvResponse, (unsigned char*)&response, &responseLen);
  tlv_free(tlvData);
  tlv_free(tlvResponse);
}

