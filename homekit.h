// HomeKit Core

#pragma once

#include <TLV8.h>

extern char bufferUrl[256];

typedef enum PairingCodesTLV8 {
    // Methods Table 4.4
    kTLVType_Method_None          = 0x00, // Custom. Reserved by spec
    kTLVType_Method_PairSetup     = 0x01,
    kTLVType_Method_PairVerify    = 0x02,
    kTLVType_Method_AddPairing    = 0x03,
    kTLVType_Method_RemovePairing = 0x04,
    kTLVType_Method_ListPairings  = 0x05,
    
    // States
    kTLVType_State_None           = 0x00,  // Custom. Reserved by spec
    kTLVType_State_M1             = 0x01,
    kTLVType_State_M2             = 0x02,
    kTLVType_State_M3             = 0x03,
    kTLVType_State_M4             = 0x04,
    kTLVType_State_M5             = 0x05,
    kTLVType_State_M6             = 0x06,
        
    // Errors Table 4.5
    kTLVError_Success             = 0x00,  // Custom. Reserved by spec
    kTLVError_Unknown             = 0x01,
    kTLVError_Authentication      = 0x02,
    kTLVError_Backoff             = 0x03,
    kTLVError_MaxPeers            = 0x04,
    kTLVError_MaxTries            = 0x05,
    kTLVError_Unavailable         = 0x06,
    kTLVError_Busy                = 0x07,
    
    // Data Types Table 5.6
    kTLVType_Method               = 0x01,
    
    kTLVType_Identifier_Device    = 0x01,
    kTLVType_Identifier_Accessory = 0x01,
    
    kTLVType_Salt                 = 0x02,
    
    kTLVType_PublicKey_Accessory  = 0x03,
    kTLVType_PublicKey_Device     = 0x03,
    
    kTLVType_Proof_Device         = 0x04,
    kTLVType_Proof_Accessory      = 0x04,
    
    kTLVType_EncryptedData_Device = 0x05,
    kTLVType_EncryptedData_Accessory = 0x05,
    
    kTLVType_State                = 0x06,
    
    kTLVType_Error                = 0x07,
    
    kTLVType_RetryDelay           = 0x08,
    kTLVType_Certificate          = 0x09,
    
    kTLVType_Signature_Device     = 0x0A,
    kTLVType_Signature_Accessory  = 0x0A,
    
    kTLVType_Permissions          = 0x0B,
    kTLVType_FragmentData         = 0x0C,
    kTLVType_FragmentLast         = 0x0D,
    kTLVType_Separator            = 0xFF
    
} PairingCodesTLV8_t;

PairingCodesTLV8_t hk_state = kTLVType_Method_None;
PairingCodesTLV8_t method = kTLVType_Method_None;

TLV8Class tlv8;

void pairing() {
  struct tlv_map PairTagTLV8;
  memset(&PairTagTLV8, 0, sizeof(tlv_map));  

  tlv8.decode( raw, len, &PairTagTLV8 );
}

