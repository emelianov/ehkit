// Template data for SRP auth
#pragma once

/*
extern "C" void srp_user_delete(struct SRPUser *usr);
extern "C" int srp_user_is_authenticated(struct SRPUser *usr);
extern "C" const char *srp_user_get_username(struct SRPUser *usr);
extern "C" const unsigned char *srp_user_get_session_key(struct SRPUser *usr, size_t *key_length);
extern "C" size_t srp_user_get_session_key_length(struct SRPUser *usr);
extern "C" void srp_user_process_challenge(struct SRPUser *usr, const unsigned char *bytes_s, size_t len_s, const unsigned char *bytes_B, size_t len_B, unsigned char **bytes_M, size_t *len_M);
extern "C" void srp_user_verify_session(struct SRPUser *usr, const unsigned char *bytes_HAMK);
extern "C" const char* srp_user_bytes_A(struct SRPUser *usr);
extern "C" void srp_verifier_delete(struct SRPVerifier *ver);
extern "C" const unsigned char *srp_user_get_session_key(struct SRPUser *usr, size_t *key_length);
extern "C" size_t srp_user_get_session_key_length(struct SRPUser *usr);
extern "C" const unsigned char *srp_verifier_get_session_key(struct SRPVerifier *ver, size_t *key_length);
extern "C" size_t srp_verifier_get_session_key_length(struct SRPVerifier *ver);
extern "C" void srp_verifier_verify_session(struct SRPVerifier *ver, const unsigned char *user_M, unsigned char **bytes_HAMK);
*/
#define CPU_OVERCLOCK

extern "C" {
 #include "srp.h"
}

extern "C" SRP_Result srp_create_salted_verification_key(SRP_HashAlgorithm alg,
                                                         SRP_NGType ng_type, const char *username_for_verifier,
                                                         const unsigned char *password, size_t len_password,
                                                         unsigned char **bytes_s,  size_t *len_s,
                                                         unsigned char **bytes_v, size_t *len_v,
                                                         const char *n_hex, const char *g_hex);
extern "C" struct SRPVerifier* srp_verifier_new(SRP_HashAlgorithm alg, SRP_NGType ng_type,
                                                const char *username,
                                                const unsigned char *bytes_s, size_t len_s,
                                                const unsigned char *bytes_v, size_t len_v,
                                                const unsigned char *bytes_A, size_t len_A,
                                                const unsigned char *bytes_b, size_t len_b,
                                                unsigned char** bytes_B, size_t *len_B,
                                                const char* n_hex, const char* g_hex);
extern "C" struct SRPUser *srp_user_new(SRP_HashAlgorithm alg, SRP_NGType ng_type,
                                        const char *username, const char *username_for_verifier,
                                        const unsigned char *bytes_password, size_t len_password, const char *n_hex,
                                        const char *g_hex);
extern "C" SRP_Result srp_user_start_authentication(struct SRPUser* usr, char **username,
                                                    const unsigned char *bytes_a, size_t len_a,
                                                    unsigned char **bytes_A, size_t* len_A);


// The test vectors from
// https://tools.ietf.org/html/rfc5054#appendix-B

static const char srp_5054_salt[] = {
      0xBE, 0xB2, 0x53, 0x79, 0xD1, 0xA8, 0x58, 0x1E, 0xB5, 0xA7, 0x27, 0x67, 0x3A, 0x24,
      0x41, 0xEE,
};


static const char srp_5054_v[] = {
      0x9B, 0x5E, 0x06, 0x17, 0x01, 0xEA, 0x7A, 0xEB, 0x39, 0xCF, 0x6E, 0x35, 0x19, 0x65, 0x5A, 0x85, 0x3C, 0xF9, 0x4C, 0x75, 0xCA, 0xF2, 0x55, 0x5E, 0xF1, 0xFA, 0xF7, 0x59, 0xBB, 0x79, 0xCB, 0x47,
      0x70, 0x14, 0xE0, 0x4A, 0x88, 0xD6, 0x8F, 0xFC, 0x05, 0x32, 0x38, 0x91, 0xD4, 0xC2, 0x05, 0xB8, 0xDE, 0x81, 0xC2, 0xF2, 0x03, 0xD8, 0xFA, 0xD1, 0xB2, 0x4D, 0x2C, 0x10, 0x97, 0x37, 0xF1, 0xBE,
      0xBB, 0xD7, 0x1F, 0x91, 0x24, 0x47, 0xC4, 0xA0, 0x3C, 0x26, 0xB9, 0xFA, 0xD8, 0xED, 0xB3, 0xE7, 0x80, 0x77, 0x8E, 0x30, 0x25, 0x29, 0xED, 0x1E, 0xE1, 0x38, 0xCC, 0xFC, 0x36, 0xD4, 0xBA, 0x31,
      0x3C, 0xC4, 0x8B, 0x14, 0xEA, 0x8C, 0x22, 0xA0, 0x18, 0x6B, 0x22, 0x2E, 0x65, 0x5F, 0x2D, 0xF5, 0x60, 0x3F, 0xD7, 0x5D, 0xF7, 0x6B, 0x3B, 0x08, 0xFF, 0x89, 0x50, 0x06, 0x9A, 0xDD, 0x03, 0xA7,
      0x54, 0xEE, 0x4A, 0xE8, 0x85, 0x87, 0xCC, 0xE1, 0xBF, 0xDE, 0x36, 0x79, 0x4D, 0xBA, 0xE4, 0x59, 0x2B, 0x7B, 0x90, 0x4F, 0x44, 0x2B, 0x04, 0x1C, 0xB1, 0x7A, 0xEB, 0xAD, 0x1E, 0x3A, 0xEB, 0xE3,
      0xCB, 0xE9, 0x9D, 0xE6, 0x5F, 0x4B, 0xB1, 0xFA, 0x00, 0xB0, 0xE7, 0xAF, 0x06, 0x86, 0x3D, 0xB5, 0x3B, 0x02, 0x25, 0x4E, 0xC6, 0x6E, 0x78, 0x1E, 0x3B, 0x62, 0xA8, 0x21, 0x2C, 0x86, 0xBE, 0xB0,
      0xD5, 0x0B, 0x5B, 0xA6, 0xD0, 0xB4, 0x78, 0xD8, 0xC4, 0xE9, 0xBB, 0xCE, 0xC2, 0x17, 0x65, 0x32, 0x6F, 0xBD, 0x14, 0x05, 0x8D, 0x2B, 0xBD, 0xE2, 0xC3, 0x30, 0x45, 0xF0, 0x38, 0x73, 0xE5, 0x39,
      0x48, 0xD7, 0x8B, 0x79, 0x4F, 0x07, 0x90, 0xE4, 0x8C, 0x36, 0xAE, 0xD6, 0xE8, 0x80, 0xF5, 0x57, 0x42, 0x7B, 0x2F, 0xC0, 0x6D, 0xB5, 0xE1, 0xE2, 0xE1, 0xD7, 0xE6, 0x61, 0xAC, 0x48, 0x2D, 0x18,
      0xE5, 0x28, 0xD7, 0x29, 0x5E, 0xF7, 0x43, 0x72, 0x95, 0xFF, 0x1A, 0x72, 0xD4, 0x02, 0x77, 0x17, 0x13, 0xF1, 0x68, 0x76, 0xDD, 0x05, 0x0A, 0xE5, 0xB7, 0xAD, 0x53, 0xCC, 0xB9, 0x08, 0x55, 0xC9,
      0x39, 0x56, 0x64, 0x83, 0x58, 0xAD, 0xFD, 0x96, 0x64, 0x22, 0xF5, 0x24, 0x98, 0x73, 0x2D, 0x68, 0xD1, 0xD7, 0xFB, 0xEF, 0x10, 0xD7, 0x80, 0x34, 0xAB, 0x8D, 0xCB, 0x6F, 0x0F, 0xCF, 0x88, 0x5C,
      0xC2, 0xB2, 0xEA, 0x2C, 0x3E, 0x6A, 0xC8, 0x66, 0x09, 0xEA, 0x05, 0x8A, 0x9D, 0xA8, 0xCC, 0x63, 0x53, 0x1D, 0xC9, 0x15, 0x41, 0x4D, 0xF5, 0x68, 0xB0, 0x94, 0x82, 0xDD, 0xAC, 0x19, 0x54, 0xDE,
      0xC7, 0xEB, 0x71, 0x4F, 0x6F, 0xF7, 0xD4, 0x4C, 0xD5, 0xB8, 0x6F, 0x6B, 0xD1, 0x15, 0x81, 0x09, 0x30, 0x63, 0x7C, 0x01, 0xD0, 0xF6, 0x01, 0x3B, 0xC9, 0x74, 0x0F, 0xA2, 0xC6, 0x33, 0xBA, 0x89
};

static const char srp_5054_a[] = {
        0x60, 0x97, 0x55, 0x27, 0x03, 0x5C, 0xF2, 0xAD, 0x19, 0x89, 0x80, 0x6F, 0x04, 0x07,
        0x21, 0x0B, 0xC8, 0x1E, 0xDC, 0x04, 0xE2, 0x76, 0x2A, 0x56, 0xAF, 0xD5, 0x29, 0xDD,
        0xDA, 0x2D, 0x43, 0x93
};

static const char srp_5054_A[] = {
        0xFA, 0xB6, 0xF5, 0xD2, 0x61, 0x5D, 0x1E, 0x32, 0x35, 0x12, 0xE7, 0x99, 0x1C, 0xC3, 0x74, 0x43, 0xF4, 0x87, 0xDA, 0x60, 0x4C, 0xA8, 0xC9, 0x23, 0x0F, 0xCB, 0x04, 0xE5,
        0x41, 0xDC, 0xE6, 0x28, 0x0B, 0x27, 0xCA, 0x46, 0x80, 0xB0, 0x37, 0x4F, 0x17, 0x9D, 0xC3, 0xBD, 0xC7, 0x55, 0x3F, 0xE6, 0x24, 0x59, 0x79, 0x8C, 0x70, 0x1A, 0xD8, 0x64,
        0xA9, 0x13, 0x90, 0xA2, 0x8C, 0x93, 0xB6, 0x44, 0xAD, 0xBF, 0x9C, 0x00, 0x74, 0x5B, 0x94, 0x2B, 0x79, 0xF9, 0x01, 0x2A, 0x21, 0xB9, 0xB7, 0x87, 0x82, 0x31, 0x9D, 0x83,
        0xA1, 0xF8, 0x36, 0x28, 0x66, 0xFB, 0xD6, 0xF4, 0x6B, 0xFC, 0x0D, 0xDB, 0x2E, 0x1A, 0xB6, 0xE4, 0xB4, 0x5A, 0x99, 0x06, 0xB8, 0x2E, 0x37, 0xF0, 0x5D, 0x6F, 0x97, 0xF6,
        0xA3, 0xEB, 0x6E, 0x18, 0x20, 0x79, 0x75, 0x9C, 0x4F, 0x68, 0x47, 0x83, 0x7B, 0x62, 0x32, 0x1A, 0xC1, 0xB4, 0xFA, 0x68, 0x64, 0x1F, 0xCB, 0x4B, 0xB9, 0x8D, 0xD6, 0x97,
        0xA0, 0xC7, 0x36, 0x41, 0x38, 0x5F, 0x4B, 0xAB, 0x25, 0xB7, 0x93, 0x58, 0x4C, 0xC3, 0x9F, 0xC8, 0xD4, 0x8D, 0x4B, 0xD8, 0x67, 0xA9, 0xA3, 0xC1, 0x0F, 0x8E, 0xA1, 0x21,
        0x70, 0x26, 0x8E, 0x34, 0xFE, 0x3B, 0xBE, 0x6F, 0xF8, 0x99, 0x98, 0xD6, 0x0D, 0xA2, 0xF3, 0xE4, 0x28, 0x3C, 0xBE, 0xC1, 0x39, 0x3D, 0x52, 0xAF, 0x72, 0x4A, 0x57, 0x23,
        0x0C, 0x60, 0x4E, 0x9F, 0xBC, 0xE5, 0x83, 0xD7, 0x61, 0x3E, 0x6B, 0xFF, 0xD6, 0x75, 0x96, 0xAD, 0x12, 0x1A, 0x87, 0x07, 0xEE, 0xC4, 0x69, 0x44, 0x95, 0x70, 0x33, 0x68,
        0x6A, 0x15, 0x5F, 0x64, 0x4D, 0x5C, 0x58, 0x63, 0xB4, 0x8F, 0x61, 0xBD, 0xBF, 0x19, 0xA5, 0x3E, 0xAB, 0x6D, 0xAD, 0x0A, 0x18, 0x6B, 0x8C, 0x15, 0x2E, 0x5F, 0x5D, 0x8C,
        0xAD, 0x4B, 0x0E, 0xF8, 0xAA, 0x4E, 0xA5, 0x00, 0x88, 0x34, 0xC3, 0xCD, 0x34, 0x2E, 0x5E, 0x0F, 0x16, 0x7A, 0xD0, 0x45, 0x92, 0xCD, 0x8B, 0xD2, 0x79, 0x63, 0x93, 0x98,
        0xEF, 0x9E, 0x11, 0x4D, 0xFA, 0xAA, 0xB9, 0x19, 0xE1, 0x4E, 0x85, 0x09, 0x89, 0x22, 0x4D, 0xDD, 0x98, 0x57, 0x6D, 0x79, 0x38, 0x5D, 0x22, 0x10, 0x90, 0x2E, 0x9F, 0x9B,
        0x1F, 0x2D, 0x86, 0xCF, 0xA4, 0x7E, 0xE2, 0x44, 0x63, 0x54, 0x65, 0xF7, 0x10, 0x58, 0x42, 0x1A, 0x01, 0x84, 0xBE, 0x51, 0xDD, 0x10, 0xCC, 0x9D, 0x07, 0x9E, 0x6F, 0x16,
        0x04, 0xE7, 0xAA, 0x9B, 0x7C, 0xF7, 0x88, 0x3C, 0x7D, 0x4C, 0xE1, 0x2B, 0x06, 0xEB, 0xE1, 0x60, 0x81, 0xE2, 0x3F, 0x27, 0xA2, 0x31, 0xD1, 0x84, 0x32, 0xD7, 0xD1, 0xBB,
        0x55, 0xC2, 0x8A, 0xE2, 0x1F, 0xFC, 0xF0, 0x05, 0xF5, 0x75, 0x28, 0xD1, 0x5A, 0x88, 0x88, 0x1B, 0xB3, 0xBB, 0xB7, 0xFE
};

static const char srp_5054_b[] = {
        0xE4, 0x87, 0xCB, 0x59, 0xD3, 0x1A, 0xC5, 0x50, 0x47, 0x1E, 0x81, 0xF0, 0x0F, 0x69,
        0x28, 0xE0, 0x1D, 0xDA, 0x08, 0xE9, 0x74, 0xA0, 0x04, 0xF4, 0x9E, 0x61, 0xF5, 0xD1,
        0x05, 0x28, 0x4D, 0x20
};

static const char srp_5054_B[] = {
        0x40, 0xF5, 0x70, 0x88, 0xA4, 0x82, 0xD4, 0xC7, 0x73, 0x33, 0x84, 0xFE, 0x0D, 0x30, 0x1F, 0xDD, 0xCA, 0x90, 0x80, 0xAD, 0x7D, 0x4F, 0x6F, 0xDF, 0x09, 0xA0, 0x10, 0x06, 0xC3, 0xCB, 0x6D, 0x56,
        0x2E, 0x41, 0x63, 0x9A, 0xE8, 0xFA, 0x21, 0xDE, 0x3B, 0x5D, 0xBA, 0x75, 0x85, 0xB2, 0x75, 0x58, 0x9B, 0xDB, 0x27, 0x98, 0x63, 0xC5, 0x62, 0x80, 0x7B, 0x2B, 0x99, 0x08, 0x3C, 0xD1, 0x42, 0x9C,
        0xDB, 0xE8, 0x9E, 0x25, 0xBF, 0xBD, 0x7E, 0x3C, 0xAD, 0x31, 0x73, 0xB2, 0xE3, 0xC5, 0xA0, 0xB1, 0x74, 0xDA, 0x6D, 0x53, 0x91, 0xE6, 0xA0, 0x6E, 0x46, 0x5F, 0x03, 0x7A, 0x40, 0x06, 0x25, 0x48,
        0x39, 0xA5, 0x6B, 0xF7, 0x6D, 0xA8, 0x4B, 0x1C, 0x94, 0xE0, 0xAE, 0x20, 0x85, 0x76, 0x15, 0x6F, 0xE5, 0xC1, 0x40, 0xA4, 0xBA, 0x4F, 0xFC, 0x9E, 0x38, 0xC3, 0xB0, 0x7B, 0x88, 0x84, 0x5F, 0xC6,
        0xF7, 0xDD, 0xDA, 0x93, 0x38, 0x1F, 0xE0, 0xCA, 0x60, 0x84, 0xC4, 0xCD, 0x2D, 0x33, 0x6E, 0x54, 0x51, 0xC4, 0x64, 0xCC, 0xB6, 0xEC, 0x65, 0xE7, 0xD1, 0x6E, 0x54, 0x8A, 0x27, 0x3E, 0x82, 0x62,
        0x84, 0xAF, 0x25, 0x59, 0xB6, 0x26, 0x42, 0x74, 0x21, 0x59, 0x60, 0xFF, 0xF4, 0x7B, 0xDD, 0x63, 0xD3, 0xAF, 0xF0, 0x64, 0xD6, 0x13, 0x7A, 0xF7, 0x69, 0x66, 0x1C, 0x9D, 0x4F, 0xEE, 0x47, 0x38,
        0x26, 0x03, 0xC8, 0x8E, 0xAA, 0x09, 0x80, 0x58, 0x1D, 0x07, 0x75, 0x84, 0x61, 0xB7, 0x77, 0xE4, 0x35, 0x6D, 0xDA, 0x58, 0x35, 0x19, 0x8B, 0x51, 0xFE, 0xEA, 0x30, 0x8D, 0x70, 0xF7, 0x54, 0x50,
        0xB7, 0x16, 0x75, 0xC0, 0x8C, 0x7D, 0x83, 0x02, 0xFD, 0x75, 0x39, 0xDD, 0x1F, 0xF2, 0xA1, 0x1C, 0xB4, 0x25, 0x8A, 0xA7, 0x0D, 0x23, 0x44, 0x36, 0xAA, 0x42, 0xB6, 0xA0, 0x61, 0x5F, 0x3F, 0x91,
        0x5D, 0x55, 0xCC, 0x3B, 0x96, 0x6B, 0x27, 0x16, 0xB3, 0x6E, 0x4D, 0x1A, 0x06, 0xCE, 0x5E, 0x5D, 0x2E, 0xA3, 0xBE, 0xE5, 0xA1, 0x27, 0x0E, 0x87, 0x51, 0xDA, 0x45, 0xB6, 0x0B, 0x99, 0x7B, 0x0F,
        0xFD, 0xB0, 0xF9, 0x96, 0x2F, 0xEE, 0x4F, 0x03, 0xBE, 0xE7, 0x80, 0xBA, 0x0A, 0x84, 0x5B, 0x1D, 0x92, 0x71, 0x42, 0x17, 0x83, 0xAE, 0x66, 0x01, 0xA6, 0x1E, 0xA2, 0xE3, 0x42, 0xE4, 0xF2, 0xE8,
        0xBC, 0x93, 0x5A, 0x40, 0x9E, 0xAD, 0x19, 0xF2, 0x21, 0xBD, 0x1B, 0x74, 0xE2, 0x96, 0x4D, 0xD1, 0x9F, 0xC8, 0x45, 0xF6, 0x0E, 0xFC, 0x09, 0x33, 0x8B, 0x60, 0xB6, 0xB2, 0x56, 0xD8, 0xCA, 0xC8,
        0x89, 0xCC, 0xA3, 0x06, 0xCC, 0x37, 0x0A, 0x0B, 0x18, 0xC8, 0xB8, 0x86, 0xE9, 0x5D, 0xA0, 0xAF, 0x52, 0x35, 0xFE, 0xF4, 0x39, 0x30, 0x20, 0xD2, 0xB7, 0xF3, 0x05, 0x69, 0x04, 0x75, 0x90, 0x42
};

// This isn't used (yet)
static const char srp_5054_u[] = {
  0xCE, 0x38, 0xB9, 0x59, 0x34, 0x87, 0xDA, 0x98, 0x55, 0x4E, 0xD4, 0x7D, 0x70, 0xA7,
  0xAE, 0x5F, 0x46, 0x2E, 0xF0, 0x19,
};

// This is SHA-512(<premaster secret>?) Session key
static const char srp_5054_S[] = {
      0x5C, 0xBC, 0x21, 0x9D, 0xB0, 0x52, 0x13, 0x8E, 0xE1, 0x14, 0x8C, 0x71, 0xCD, 0x44, 0x98, 0x96, 0x3D, 0x68, 0x25, 0x49, 0xCE, 0x91, 0xCA, 0x24, 0xF0, 0x98, 0x46, 0x8F, 0x06, 0x01, 0x5B, 0xEB,
      0x6A, 0xF2, 0x45, 0xC2, 0x09, 0x3F, 0x98, 0xC3, 0x65, 0x1B, 0xCA, 0x83, 0xAB, 0x8C, 0xAB, 0x2B, 0x58, 0x0B, 0xBF, 0x02, 0x18, 0x4F, 0xEF, 0xDF, 0x26, 0x14, 0x2F, 0x73, 0xDF, 0x95, 0xAC, 0x50
};

// Premaster key
static const char srp_5054_P[] = {
        0xF1, 0x03, 0x6F, 0xEC, 0xD0, 0x17, 0xC8, 0x23, 0x9C, 0x0D, 0x5A, 0xF7, 0xE0, 0xFC, 0xF0, 0xD4, 0x08, 0xB0, 0x09, 0xE3, 0x64, 0x11, 0x61, 0x8A, 0x60, 0xB2, 0x3A, 0xAB, 0xBF, 0xC3, 0x83, 0x39,
        0x72, 0x68, 0x23, 0x12, 0x14, 0xBA, 0xAC, 0xDC, 0x94, 0xCA, 0x1C, 0x53, 0xF4, 0x42, 0xFB, 0x51, 0xC1, 0xB0, 0x27, 0xC3, 0x18, 0xAE, 0x23, 0x8E, 0x16, 0x41, 0x4D, 0x60, 0xD1, 0x88, 0x1B, 0x66,
        0x48, 0x6A, 0xDE, 0x10, 0xED, 0x02, 0xBA, 0x33, 0xD0, 0x98, 0xF6, 0xCE, 0x9B, 0xCF, 0x1B, 0xB0, 0xC4, 0x6C, 0xA2, 0xC4, 0x7F, 0x2F, 0x17, 0x4C, 0x59, 0xA9, 0xC6, 0x1E, 0x25, 0x60, 0x89, 0x9B,
        0x83, 0xEF, 0x61, 0x13, 0x1E, 0x6F, 0xB3, 0x0B, 0x71, 0x4F, 0x4E, 0x43, 0xB7, 0x35, 0xC9, 0xFE, 0x60, 0x80, 0x47, 0x7C, 0x1B, 0x83, 0xE4, 0x09, 0x3E, 0x4D, 0x45, 0x6B, 0x9B, 0xCA, 0x49, 0x2C,
        0xF9, 0x33, 0x9D, 0x45, 0xBC, 0x42, 0xE6, 0x7C, 0xE6, 0xC0, 0x2C, 0x24, 0x3E, 0x49, 0xF5, 0xDA, 0x42, 0xA8, 0x69, 0xEC, 0x85, 0x57, 0x80, 0xE8, 0x42, 0x07, 0xB8, 0xA1, 0xEA, 0x65, 0x01, 0xC4,
        0x78, 0xAA, 0xC0, 0xDF, 0xD3, 0xD2, 0x26, 0x14, 0xF5, 0x31, 0xA0, 0x0D, 0x82, 0x6B, 0x79, 0x54, 0xAE, 0x8B, 0x14, 0xA9, 0x85, 0xA4, 0x29, 0x31, 0x5E, 0x6D, 0xD3, 0x66, 0x4C, 0xF4, 0x71, 0x81,
        0x49, 0x6A, 0x94, 0x32, 0x9C, 0xDE, 0x80, 0x05, 0xCA, 0xE6, 0x3C, 0x2F, 0x9C, 0xA4, 0x96, 0x9B, 0xFE, 0x84, 0x00, 0x19, 0x24, 0x03, 0x7C, 0x44, 0x65, 0x59, 0xBD, 0xBB, 0x9D, 0xB9, 0xD4, 0xDD,
        0x14, 0x2F, 0xBC, 0xD7, 0x5E, 0xEF, 0x2E, 0x16, 0x2C, 0x84, 0x30, 0x65, 0xD9, 0x9E, 0x8F, 0x05, 0x76, 0x2C, 0x4D, 0xB7, 0xAB, 0xD9, 0xDB, 0x20, 0x3D, 0x41, 0xAC, 0x85, 0xA5, 0x8C, 0x05, 0xBD,
        0x4E, 0x2D, 0xBF, 0x82, 0x2A, 0x93, 0x45, 0x23, 0xD5, 0x4E, 0x06, 0x53, 0xD3, 0x76, 0xCE, 0x8B, 0x56, 0xDC, 0xB4, 0x52, 0x7D, 0xDD, 0xC1, 0xB9, 0x94, 0xDC, 0x75, 0x09, 0x46, 0x3A, 0x74, 0x68,
        0xD7, 0xF0, 0x2B, 0x1B, 0xEB, 0x16, 0x85, 0x71, 0x4C, 0xE1, 0xDD, 0x1E, 0x71, 0x80, 0x8A, 0x13, 0x7F, 0x78, 0x88, 0x47, 0xB7, 0xC6, 0xB7, 0xBF, 0xA1, 0x36, 0x44, 0x74, 0xB3, 0xB7, 0xE8, 0x94,
        0x78, 0x95, 0x4F, 0x6A, 0x8E, 0x68, 0xD4, 0x5B, 0x85, 0xA8, 0x8E, 0x4E, 0xBF, 0xEC, 0x13, 0x36, 0x8E, 0xC0, 0x89, 0x1C, 0x3B, 0xC8, 0x6C, 0xF5, 0x00, 0x97, 0x88, 0x01, 0x78, 0xD8, 0x61, 0x35,
        0xE7, 0x28, 0x72, 0x34, 0x58, 0x53, 0x88, 0x58, 0xD7, 0x15, 0xB7, 0xB2, 0x47, 0x40, 0x62, 0x22, 0xC1, 0x01, 0x9F, 0x53, 0x60, 0x3F, 0x01, 0x69, 0x52, 0xD4, 0x97, 0x10, 0x08, 0x58, 0x82, 0x4C
};

int test_rfc_5054_compat()
{
  struct SRPVerifier *ver;
  struct SRPUser *usr;

  size_t len_s = 16;
  unsigned char *bytes_s = 0;
  bytes_s = (unsigned char*)malloc(sizeof(srp_5054_salt));
  memcpy(bytes_s, srp_5054_salt, sizeof(srp_5054_salt));

  size_t len_v = 0;
  unsigned char *bytes_v = 0;

  size_t len_A = 0;
  unsigned char *bytes_A = 0;
  
  size_t len_B = 0;
  unsigned char *bytes_B = 0;
  
  size_t len_M = 0;
  unsigned char *bytes_M = 0;
  unsigned char *bytes_HAMK = 0;
  
  size_t len_S = 0;
  const unsigned char *bytes_S = 0;

  const char *username = "alice";
  const char *password = "password123";

  SRP_HashAlgorithm alg = SRP_SHA512;
  SRP_NGType ng_type = SRP_NG_3072;

  Serial.printf("Testing RFC 5054 test vectors...");

  srp_create_salted_verification_key(alg, ng_type, username, (const unsigned char *)password, strlen(password), &bytes_s, &len_s, &bytes_v, &len_v, NULL, NULL);
  yield();
  
  if (memcmp(&srp_5054_v, bytes_v, len_v) != 0) {
    Serial.printf(" computed v doesn't match!\n");
    return 1;
  }
  Serial.println("v is matched");

  usr = srp_user_new(alg, ng_type, username, username, (const unsigned char *)password, strlen(password), NULL, NULL);
  srp_user_start_authentication(
    usr, NULL, (unsigned char *)srp_5054_a, sizeof(srp_5054_a), &bytes_A, &len_A);

  yield();

  if (memcmp(&srp_5054_A, bytes_A, len_A) != 0) {
    Serial.printf(" computed A doesn't match!\n");
    return 1;
  }
  Serial.println("A is matched");

  /* User -> Host: (username, bytes_A) */
  ver = srp_verifier_new(alg, ng_type, username, (unsigned char *)srp_5054_salt, len_s, bytes_v, len_v, bytes_A, len_A, (unsigned char *)srp_5054_b, sizeof(srp_5054_b), &bytes_B, &len_B, NULL, NULL);

  yield();
  if (!bytes_B) {
    Serial.printf(" SRP-6a safety check violated for B!\n");
    return 1;
  }
  Serial.println("SRP check is Ok");
  
  if (memcmp(&srp_5054_B, bytes_B, len_B) != 0) {
    Serial.printf(" computed B doesn't match!\n");
    return 1;
  }
  Serial.println("B is Ok");
  
  /* Host -> User: (bytes_s, bytes_B) */
  srp_user_process_challenge(usr, (unsigned char *)srp_5054_salt, len_s, bytes_B, len_B, &bytes_M, &len_M);
  yield();
  if (!bytes_M) {
    Serial.printf(" SRP-6a safety check violated for M!\n");
    goto cleanup;
  }
  Serial.println("Challenge is Ok");
  
  /* User -> Host: (bytes_M) */
  srp_verifier_verify_session(ver, bytes_M, &bytes_HAMK);
  yield();
  if (!bytes_HAMK) {
    Serial.printf(" user authentication failed!\n");
    goto cleanup;
  }
  Serial.println("Verify ses is Ok");
  
  /* Host -> User: (HAMK) */
  srp_user_verify_session(usr, bytes_HAMK);
  yield();
  if (!srp_user_is_authenticated(usr)) {
    Serial.printf(" server authentication failed!\n");
  }
  Serial.println("User auth is Ok");
  
  bytes_S = srp_verifier_get_session_key(ver, &len_S);

  if (memcmp(&srp_5054_S, bytes_S, len_S) != 0) {
    Serial.printf(" computed session key doesn't match!\n");
    return 1;
  }

  Serial.printf(" success.\n");

cleanup:
  srp_verifier_delete(ver);
  srp_user_delete(usr);

  free(bytes_s);
  free(bytes_v);

  return 0;
}

void espOverclock() {
   REG_SET_BIT(0x3ff00014, BIT(0));
   //os_update_cpu_frequency(160);
}

void espNormal() {
    REG_CLR_BIT(0x3ff00014, BIT(0));
    //os_update_cpu_frequency(80);
}

void ICACHE_RAM_ATTR pwm_timer_isr(){
  wdt_reset();
}
void espWatchdogDisable() {
  timer1_disable();
  timer1_attachInterrupt(pwm_timer_isr);
  timer1_write(1200000);
  timer1_enable(TIM_DIV265, TIM_EDGE, TIM_LOOP);
  wdt_disable();  
}
void espWatchdogEnable() {
  timer1_disable();
  timer1_detachInterrupt();
}

uint32_t srpInit() {
  
}

