# @author Vestigo Team
# @category Analysis
# @keybinding
# @menupath
# @toolbar

import ghidra
from ghidra.program.model.block import BasicBlockModel
# The ghidra.program.model.pcode module is only available inside Ghidra's Jython environment.
# Wrap the import so that static analysis or running outside Ghidra does not fail; provide a
# minimal fallback PcodeOp shim for environments where ghidra isn't available.
try:
    from ghidra.program.model.pcode import PcodeOp
except Exception:
    class PcodeOp:
        INT_XOR = 1
        INT_AND = 2
        INT_OR = 3
        INT_LEFT = 4
        INT_RIGHT = 5
        INT_SRIGHT = 6
        INT_ADD = 7
        INT_SUB = 8
        INT_MULT = 9
        INT_DIV = 10
        INT_REM = 11
        INT_CARRY = 12
        INT_SCARRY = 13
        LOAD = 14
        STORE = 15
        BRANCH = 16
        CBRANCH = 17
        CALL = 18
        RETURN = 19
        MULTIEQUAL = 20

from ghidra.util.task import TaskMonitor
from ghidra.program.model.address import AddressSet

import json
import math
import sys
import os

# =============================================================================
# 1. CRYPTOGRAPHIC CONSTANTS DATABASE
# =============================================================================
# "Magic Numbers" that serve as high-confidence signatures.

CRYPTO_CONSTANTS = {
    # --- AES (Rijndael) ---
    # Forward S-Box (first 16 bytes packed into 32-bit integers for detection)
    "AES_SBOX": [0x637c777b, 0xf26b6fc5, 0x3001672b, 0xfed7ab76], 
    # Byte-wise S-Box for memory scanning
    "AES_SBOX_BYTES": [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    ], 
    # Inverse S-Box
    "AES_INV_SBOX": [0x52096a, 0xd53036a5, 0x38bf40a3, 0x9e81f3d7],
    # T-Table 0 (Optimization often used in OpenSSL)
    "AES_TE0":  [0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d], 
    # Rcon (Round Constants)
    "AES_RCON": [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000],

    # --- SHA Family ---
    "SHA1_K":     [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6],
    "SHA1_INIT":  [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
    
    "SHA256_K":   [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1],
    "SHA256_INIT":[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a],
    "SHA224_INIT":[0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939], 

    # --- MD5 ---
    "MD5_T":      [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee],
    "MD5_INIT":   [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],

    # --- Stream Ciphers ---
    # ChaCha20 / Salsa20 sigma constant "expand 32-byte k"
    "CHACHA_SIG": [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574], 

    # --- Asymmetric (RSA/ECC) ---
    # Curve P-256 Prime (secp256r1)
    "P256_PRIME": [0xFFFFFFFF, 0x00000001, 0x00000000, 0x00000000], 
    # Curve25519 Prime (2^255 - 19)
    "C25519_PRIME": [0x7fffffffffffffff, 0xffffffffffffffed],
    # ASN.1 Sequence Header often found in RSA keys
    "ASN1_SEQ":   [0x3082], 
    
    # --- PRNG ---
    # Mersenne Twister MT19937 Matrix A

    "MT19937_MATRIX_A": [0x9908b0df],
}

# Ground Truth Mapping
# Maps source code function names to specific cryptographic algorithm labels
# Based on actual function names extracted from compiled binaries
LABEL_MAP = {
    # ========== AES Functions ==========
    "AddRoundKey": "AES",
    "add_round_key": "AES",
    "SubBytes": "AES",
    "sub_bytes": "AES",
    "inv_sub_bytes": "AES",
    "ShiftRows": "AES",
    "shift_rows": "AES",
    "inv_shift_rows": "AES",
    "MixColumns": "AES",
    "mix_columns": "AES",
    "inv_mix_columns": "AES",
    "Subword": "AES",
    "rotword": "AES",
    "AesEncrypt_C": "AES",
    "AesSetKey_C": "AES",
    "aes_cbc_decrypt": "AES",
    "aes_cbc_encrypt": "AES",
    "aes_setkey": "AES",
    "aesgcm_GHASH": "AES",
    "IncrementAesCounter": "AES",
    # TinyCrypt AES
    "tc_aes128_set_decrypt_key": "AES",
    "tc_aes128_set_encrypt_key": "AES",
    "tc_aes_decrypt": "AES",
    "tc_aes_encrypt": "AES",
    "tc_cbc_mode_decrypt": "AES",
    "tc_cbc_mode_encrypt": "AES",
    "tc_ctr_mode": "AES",
    # WolfSSL/WolfCrypt AES
    "wc_AesCbcDecrypt": "AES",
    "wc_AesCbcEncrypt": "AES",
    "wc_AesCtrEncrypt": "AES",
    "wc_AesCtrSetKey": "AES",
    "wc_AesDelete": "AES",
    "wc_AesEncrypt": "AES",
    "wc_AesFree": "AES",
    "wc_AesGetKeySize": "AES",
    "wc_AesInit": "AES",
    "wc_AesNew": "AES",
    "wc_AesSetIV": "AES",
    "wc_AesSetKey": "AES",
    "wc_AesSetKeyDirect": "AES",
    "wc_AesSetKeyLocal": "AES",
    
    # ========== SHA/Hash Functions ==========
    "Transform_Sha256": "SHA",
    "PBKDF2_SHA256.constprop.0": "SHA",
    "sha1_begin": "SHA",
    "sha1_end": "SHA",
    "sha256_begin": "SHA",
    "sha256_block": "SHA",
    "sha384_begin": "SHA",
    "sha384_end": "SHA",
    "sha3_begin": "SHA",
    "sha3_end": "SHA",
    "sha3_hash": "SHA",
    "sha3_process_block72": "SHA",
    "sha512384_end": "SHA",
    "sha512_begin": "SHA",
    "sha512_end": "SHA",
    "sha512_hash": "SHA",
    "sha512_process_block128": "SHA",
    "sha_crypt": "SHA",
    "prf_hmac_sha256": "SHA",
    # TinyCrypt SHA
    "tc_sha256_final": "SHA",
    "tc_sha256_init": "SHA",
    "tc_sha256_update": "SHA",
    # WolfSSL SHA
    "wc_InitSha256": "SHA",
    "wc_InitSha256_ex": "SHA",
    "wc_Sha256Copy": "SHA",
    "wc_Sha256Final": "SHA",
    "wc_Sha256FinalRaw": "SHA",
    "wc_Sha256Free": "SHA",
    "wc_Sha256GetHash": "SHA",
    "wc_Sha256Update": "SHA",
    
    # ========== HMAC Functions ==========
    "hmac_begin": "HMAC",
    "hmac_block": "HMAC",
    "hmac_blocks.constprop.0": "HMAC",
    "hmac_end": "HMAC",
    "hmac_hash_v": "HMAC",
    "hmac_peek_hash": "HMAC",
    # TinyCrypt HMAC
    "tc_hmac_final": "HMAC",
    "tc_hmac_init": "HMAC",
    "tc_hmac_set_key": "HMAC",
    "tc_hmac_update": "HMAC",
    
    # ========== MD5 Functions ==========
    "md5_begin": "MD5",
    "md5_crypt": "MD5",
    "md5_end": "MD5",
    "md5_hash": "MD5",
    "md5_process_block64": "MD5",
    
    # ========== ChaCha20 Functions ==========
    "chacha20_encrypt": "ChaCha20",
    "chacha20_rounds": "ChaCha20",
    "crypto_chacha20_djb": "ChaCha20",
    "crypto_chacha20_h": "ChaCha20",
    "crypto_chacha20_ietf": "ChaCha20",
    "crypto_chacha20_x": "ChaCha20",
    # WolfSSL ChaCha
    "wc_Chacha_Process": "ChaCha20",
    "wc_Chacha_SetIV": "ChaCha20",
    "wc_Chacha_SetKey": "ChaCha20",
    "wc_Chacha_wordtobyte": "ChaCha20",
    
    # ========== Poly1305 Functions ==========
    "crypto_poly1305": "Poly1305",
    "crypto_poly1305_final": "Poly1305",
    "crypto_poly1305_init": "Poly1305",
    "crypto_poly1305_update": "Poly1305",
    "poly_blocks": "Poly1305",
    
    # ========== Salsa20 Functions ==========
    "salsa20": "Salsa20",
    "salsa20_simd_shuffle": "Salsa20",
    "salsa20_simd_unshuffle": "Salsa20",
    "blockmix_salsa8": "Salsa20",
    "blockmix_salsa8_xor": "Salsa20",
    
    # ========== Blake2b Functions ==========
    "blake2b_compress": "Blake2b",
    "blake_update_32": "Blake2b",
    "blake_update_32_buf": "Blake2b",
    "crypto_blake2b": "Blake2b",
    "crypto_blake2b_final": "Blake2b",
    "crypto_blake2b_init": "Blake2b",
    "crypto_blake2b_keyed": "Blake2b",
    "crypto_blake2b_keyed_init": "Blake2b",
    "crypto_blake2b_update": "Blake2b",
    
    # ========== AEAD Functions ==========
    "crypto_aead_init_djb": "AEAD",
    "crypto_aead_init_ietf": "AEAD",
    "crypto_aead_init_x": "AEAD",
    "crypto_aead_lock": "AEAD",
    "crypto_aead_read": "AEAD",
    "crypto_aead_unlock": "AEAD",
    "crypto_aead_write": "AEAD",
    
    # ========== Curve25519/EdDSA Functions ==========
    "curve25519": "Curve25519",
    "crypto_x25519": "Curve25519",
    "crypto_x25519_dirty_fast": "Curve25519",
    "crypto_x25519_dirty_small": "Curve25519",
    "crypto_x25519_inverse": "Curve25519",
    "crypto_x25519_public_key": "Curve25519",
    "crypto_x25519_to_eddsa": "Curve25519",
    "curve_x25519_compute_pubkey_and_premaster": "Curve25519",
    # EdDSA
    "crypto_eddsa_check": "EdDSA",
    "crypto_eddsa_check_equation": "EdDSA",
    "crypto_eddsa_key_pair": "EdDSA",
    "crypto_eddsa_mul_add": "EdDSA",
    "crypto_eddsa_reduce": "EdDSA",
    "crypto_eddsa_scalarbase": "EdDSA",
    "crypto_eddsa_sign": "EdDSA",
    "crypto_eddsa_to_x25519": "EdDSA",
    "crypto_eddsa_trim_scalar": "EdDSA",
    # Elligator
    "crypto_elligator_key_pair": "Elligator",
    "crypto_elligator_map": "Elligator",
    "crypto_elligator_rev": "Elligator",
    # Field element operations (fe_*)
    "fe_0": "Curve25519",
    "fe_1": "Curve25519",
    "fe_add": "Curve25519",
    "fe_ccopy": "Curve25519",
    "fe_copy": "Curve25519",
    "fe_cswap": "Curve25519",
    "fe_frombytes_mask": "Curve25519",
    "fe_invert": "Curve25519",
    "fe_isequal": "Curve25519",
    "fe_isodd": "Curve25519",
    "fe_mul": "Curve25519",
    "fe_mul__distinct": "Curve25519",
    "fe_mul_c": "Curve25519",
    "fe_mul_small": "Curve25519",
    "fe_neg": "Curve25519",
    "fe_reduce": "Curve25519",
    "fe_sq": "Curve25519",
    "fe_sub": "Curve25519",
    "fe_tobytes": "Curve25519",
    # Group element operations (ge_*)
    "ge_add": "EdDSA",
    "ge_cache": "EdDSA",
    "ge_double": "EdDSA",
    "ge_frombytes_neg_vartime": "EdDSA",
    "ge_madd": "EdDSA",
    "ge_scalarmult_base": "EdDSA",
    "ge_tobytes": "EdDSA",
    "ge_zero": "EdDSA",
    "scalarmult": "ECC",
    "scalar_bit": "ECC",
    
    # ========== ECC Functions (General) ==========
    "curve_P256_compute_pubkey_and_premaster": "ECC",
    "XYcZ_add": "ECC",
    "XYcZ_addC": "ECC",
    "XYcZ_initial_double": "ECC",
    "double_jacobian_default": "ECC",
    # ECC Point operations
    "EccPoint_compute_public_key": "ECC",
    "EccPoint_isZero": "ECC",
    "EccPoint_mult": "ECC",
    "ecc_make_pub_ex": "ECC",
    "ecc_map": "ECC",
    "ecc_map_ex": "ECC",
    "ecc_mulmod": "ECC",
    "ecc_point_to_mont": "ECC",
    "ecc_projective_add_point": "ECC",
    "ecc_projective_add_point_safe": "ECC",
    "ecc_projective_dbl_point": "ECC",
    "ecc_projective_dbl_point_safe": "ECC",
    "_ecc_is_point": "ECC",
    "_ecc_make_key_ex": "ECC",
    "_ecc_projective_add_point": "ECC",
    "_ecc_projective_dbl_point": "ECC",
    "_ecc_validate_public_key": "ECC",
    
    # ========== WolfSSL ECC (wc_ecc_*) ==========
    "wc_ecc_check_key": "ECC",
    "wc_ecc_cmp_param": "ECC",
    "wc_ecc_cmp_point": "ECC",
    "wc_ecc_copy_point": "ECC",
    "wc_ecc_curve_cache_free_spec": "ECC",
    "wc_ecc_curve_cache_load_item": "ECC",
    "wc_ecc_curve_load": "ECC",
    "wc_ecc_del_point": "ECC",
    "wc_ecc_del_point_ex": "ECC",
    "wc_ecc_del_point_h": "ECC",
    "wc_ecc_export_ex": "ECC",
    "wc_ecc_export_point_der": "ECC",
    "wc_ecc_export_point_der_ex": "ECC",
    "wc_ecc_export_private_only": "ECC",
    "wc_ecc_export_private_raw": "ECC",
    "wc_ecc_export_public_raw": "ECC",
    "wc_ecc_export_x963": "ECC",
    "wc_ecc_export_x963_ex": "ECC",
    "wc_ecc_forcezero_point": "ECC",
    "wc_ecc_free": "ECC",
    "wc_ecc_gen_k": "ECC",
    "wc_ecc_get_curve_id": "ECC",
    "wc_ecc_get_curve_id_from_dp_params": "ECC",
    "wc_ecc_get_curve_id_from_name": "ECC",
    "wc_ecc_get_curve_id_from_oid": "ECC",
    "wc_ecc_get_curve_id_from_params": "ECC",
    "wc_ecc_get_curve_idx": "ECC",
    "wc_ecc_get_curve_idx_from_name": "ECC",
    "wc_ecc_get_curve_params": "ECC",
    "wc_ecc_get_curve_size_from_id": "ECC",
    "wc_ecc_get_curve_size_from_name": "ECC",
    "wc_ecc_get_name": "ECC",
    "wc_ecc_get_oid": "ECC",
    "wc_ecc_get_sets": "ECC",
    "wc_ecc_import_point_der": "ECC",
    "wc_ecc_import_point_der_ex": "ECC",
    "wc_ecc_import_private_key": "ECC",
    "wc_ecc_import_private_key_ex": "ECC",
    "wc_ecc_import_raw": "ECC",
    "wc_ecc_import_raw_ex": "ECC",
    "wc_ecc_import_raw_private": "ECC",
    "wc_ecc_import_unsigned": "ECC",
    "wc_ecc_import_x963": "ECC",
    "wc_ecc_import_x963_ex": "ECC",
    "wc_ecc_init": "ECC",
    "wc_ecc_init_ex": "ECC",
    "wc_ecc_is_point": "ECC",
    "wc_ecc_is_valid_idx": "ECC",
    "wc_ecc_key_free": "ECC",
    "wc_ecc_key_new": "ECC",
    "wc_ecc_make_key": "ECC",
    "wc_ecc_make_key_ex": "ECC",
    "wc_ecc_make_key_ex2": "ECC",
    "wc_ecc_make_pub": "ECC",
    "wc_ecc_make_pub_ex": "ECC",
    "wc_ecc_mulmod": "ECC",
    "wc_ecc_mulmod_ex": "ECC",
    "wc_ecc_mulmod_ex2": "ECC",
    "wc_ecc_new_point": "ECC",
    "wc_ecc_new_point_ex": "ECC",
    "wc_ecc_new_point_h": "ECC",
    "wc_ecc_point_is_at_infinity": "ECC",
    "wc_ecc_rs_raw_to_sig": "ECC",
    "wc_ecc_rs_to_sig": "ECC",
    "wc_ecc_set_curve": "ECC",
    "wc_ecc_set_flags": "ECC",
    "wc_ecc_shared_secret": "ECC",
    "wc_ecc_shared_secret_ex": "ECC",
    "wc_ecc_shared_secret_gen_sync": "ECC",
    "wc_ecc_sig_size": "ECC",
    "wc_ecc_sig_size_calc": "ECC",
    "wc_ecc_sig_to_rs": "ECC",
    "wc_ecc_sign_hash": "ECC",
    "wc_ecc_sign_hash_ex": "ECC",
    "wc_ecc_size": "ECC",
    "wc_ecc_verify_hash": "ECC",
    "wc_ecc_verify_hash_ex": "ECC",
    
    # ========== micro-ecc (uECC_*) ==========
    "uECC_compute_public_key": "ECC",
    "uECC_curve_private_key_size": "ECC",
    "uECC_curve_public_key_size": "ECC",
    "uECC_generate_random_int": "ECC",
    "uECC_get_rng": "ECC",
    "uECC_make_key": "ECC",
    "uECC_make_key_with_d": "ECC",
    "uECC_secp256r1": "ECC",
    "uECC_set_rng": "ECC",
    "uECC_shared_secret": "ECC",
    "uECC_sign": "ECC",
    "uECC_sign_with_k": "ECC",
    "uECC_valid_point": "ECC",
    "uECC_valid_public_key": "ECC",
    "uECC_verify": "ECC",
    "uECC_vli_add": "ECC",
    "uECC_vli_bytesToNative": "ECC",
    "uECC_vli_clear": "ECC",
    "uECC_vli_cmp": "ECC",
    "uECC_vli_cmp_unsafe": "ECC",
    "uECC_vli_equal": "ECC",
    "uECC_vli_isZero": "ECC",
    "uECC_vli_mmod": "ECC",
    "uECC_vli_modAdd": "ECC",
    "uECC_vli_modInv": "ECC",
    "uECC_vli_modMult": "ECC",
    "uECC_vli_modMult_fast": "ECC",
    "uECC_vli_modSquare_fast": "ECC",
    "uECC_vli_modSub": "ECC",
    "uECC_vli_mult": "ECC",
    "uECC_vli_nativeToBytes": "ECC",
    "uECC_vli_numBits": "ECC",
    "uECC_vli_rshift1": "ECC",
    "uECC_vli_set": "ECC",
    "uECC_vli_sub": "ECC",
    "uECC_vli_testBit": "ECC",
    "vli_mmod_fast_secp256r1": "ECC",
    "vli_modInv_update": "ECC",
    "vli_numDigits": "ECC",
    
    # ========== WolfSSL SP Math (sp_*) ==========
    "sp_256_add_8": "ECC",
    "sp_256_cmp_8": "ECC",
    "sp_256_ecc_mulmod_8": "ECC",
    "sp_256_from_bin_8": "ECC",
    "sp_256_mod_mul_norm_8": "ECC",
    "sp_256_mont_dbl_8": "ECC",
    "sp_256_mont_mul_8": "ECC",
    "sp_256_mont_mul_and_reduce_8": "ECC",
    "sp_256_mont_sqr_8": "ECC",
    "sp_256_mont_sub_8": "ECC",
    "sp_256_point_from_bin2x32": "ECC",
    "sp_256_proj_point_add_8": "ECC",
    "sp_256_proj_point_dbl_8.part.0": "ECC",
    "sp_256_sub_8": "ECC",
    "sp_256_sub_8_p256_mod": "ECC",
    "sp_256_to_bin_8": "ECC",
    "sp_512to256_mont_reduce_8": "ECC",
    
    # ========== RSA Functions ==========
    "psRsaEncryptPub": "RSA",
    "RsaFunctionCheckIn": "RSA",
    "RsaGetValue": "RSA",
    "RsaMGF": "RSA",
    "RsaMGF1": "RSA",
    "RsaPad_OAEP": "RSA",
    "RsaPrivateDecryptEx": "RSA",
    "RsaPublicEncryptEx": "RSA",
    "RsaUnPad_OAEP": "RSA",
    # WolfSSL RSA
    "wc_DeleteRsaKey": "RSA",
    "wc_FreeRsaKey": "RSA",
    "wc_hash2mgf": "RSA",
    "wc_InitRsaKey": "RSA",
    "wc_InitRsaKey_ex": "RSA",
    "wc_NewRsaKey": "RSA",
    "wc_RsaCleanup": "RSA",
    "wc_RsaEncryptSize": "RSA",
    "wc_RsaExportKey": "RSA",
    "wc_RsaFlattenPublicKey": "RSA",
    "wc_RsaFunction": "RSA",
    "wc_RsaFunction_ex": "RSA",
    "wc_RsaPad_ex": "RSA",
    "wc_RsaPrivateDecrypt": "RSA",
    "wc_RsaPrivateDecryptInline": "RSA",
    "wc_RsaPrivateDecryptInline_ex": "RSA",
    "wc_RsaPrivateDecrypt_ex": "RSA",
    "wc_RsaPrivateKeyDecodeRaw": "RSA",
    "wc_RsaPublicEncrypt": "RSA",
    "wc_RsaPublicEncrypt_ex": "RSA",
    "wc_RsaSSL_Sign": "RSA",
    "wc_RsaSSL_Verify": "RSA",
    "wc_RsaSSL_VerifyInline": "RSA",
    "wc_RsaSSL_Verify_ex": "RSA",
    "wc_RsaSSL_Verify_ex2": "RSA",
    "wc_RsaUnPad_ex": "RSA",
    
    # ========== Big Integer Math (pstm_*) ==========
    "pstm_add": "RSA",
    "pstm_clamp": "RSA",
    "pstm_clear": "RSA",
    "pstm_cmp": "RSA",
    "pstm_cmp_mag": "RSA",
    "pstm_copy": "RSA",
    "pstm_count_bits": "RSA",
    "pstm_div_2d.constprop.0.isra.0": "RSA",
    "pstm_exptmod": "RSA",
    "pstm_grow": "RSA",
    "pstm_init_for_read_unsigned_bin": "RSA",
    "pstm_init_size": "RSA",
    "pstm_lshd.isra.0": "RSA",
    "pstm_mod": "RSA",
    "pstm_montgomery_reduce": "RSA",
    "pstm_mul_2": "RSA",
    "pstm_mul_2d.constprop.0.isra.0": "RSA",
    "pstm_mul_comba": "RSA",
    "pstm_mul_d.isra.0": "RSA",
    "pstm_mulmod": "RSA",
    "pstm_read_unsigned_bin": "RSA",
    "pstm_rshd": "RSA",
    "pstm_sqr_comba": "RSA",
    "pstm_sub": "RSA",
    "pstm_to_unsigned_bin": "RSA",
    "pstm_unsigned_bin_size": "RSA",
    "pstm_zero": "RSA",
    "s_pstm_sub": "RSA",
    "der_binary_to_pstm": "RSA",
    
    # ========== Diffie-Hellman Functions ==========
    "DhSetKey": "DH",
    "GeneratePrivateDh186": "DH",
    "GeneratePublicDh": "DH",
    "_ffc_pairwise_consistency_test": "DH",
    "_ffc_validate_public_key": "DH",
    # WolfSSL DH
    "wc_DhAgree": "DH",
    "wc_DhAgree_Sync": "DH",
    "wc_DhAgree_ct": "DH",
    "wc_DhCheckKeyPair": "DH",
    "wc_DhCheckPrivKey": "DH",
    "wc_DhCheckPrivKey_ex": "DH",
    "wc_DhCheckPubKey": "DH",
    "wc_DhCheckPubKey_ex": "DH",
    "wc_DhCheckPubValue": "DH",
    "wc_DhCopyNamedKey": "DH",
    "wc_DhExportParamsRaw": "DH",
    "wc_DhGenerateKeyPair": "DH",
    "wc_DhGeneratePublic": "DH",
    "wc_DhGetNamedKeyParamSize": "DH",
    "wc_DhSetCheckKey": "DH",
    "wc_DhSetKey": "DH",
    "wc_DhSetKey_ex": "DH",
    "wc_DhSetNamedKey": "DH",
    "wc_FreeDhKey": "DH",
    "wc_InitDhKey": "DH",
    "wc_InitDhKey_ex": "DH",
    
    # ========== Utility/Helper Crypto Functions ==========
    "bits2int": "Utility",
    "dec_vli": "Utility",
    "xorbuf": "Utility",
    "xorbuf16": "Utility",
    "xorbuf16_aligned_long": "Utility",
    "xorbuf64_3_aligned64": "Utility",
    "xorbuf_3": "Utility",
    "xorbufout": "Utility",
    "crypto_verify16": "Utility",
    "crypto_verify32": "Utility",
    "crypto_verify64": "Utility",
    "crypto_wipe": "Utility",
    
    # ========== Password/KDF Functions ==========
    "crypto_argon2": "KDF",
    "blockmix": "KDF",
    "blockmix_xor": "KDF",
    "blockmix_xor_save": "KDF",
    "smix1": "KDF",
    "smix2": "KDF",
    "yescrypt_kdf32_body.constprop.0": "KDF",
    "yescrypt_r": "KDF",
    "crypt_make_pw_salt": "KDF",
    "crypt_make_rand64encoded": "KDF",
    "pw_encrypt": "KDF",
    "des_crypt": "DES"
}

# Mapping P-Code IDs to readable strings for histograms
PCODE_MAP = {
    PcodeOp.INT_XOR: "XOR", PcodeOp.INT_AND: "AND", PcodeOp.INT_OR: "OR",
    PcodeOp.INT_LEFT: "SHL", PcodeOp.INT_RIGHT: "SHR", PcodeOp.INT_SRIGHT: "SAR",
    PcodeOp.INT_ADD: "ADD", PcodeOp.INT_SUB: "SUB", PcodeOp.INT_MULT: "MUL",
    PcodeOp.INT_DIV: "DIV", PcodeOp.INT_REM: "MOD",
    PcodeOp.INT_CARRY: "CARRY", PcodeOp.INT_SCARRY: "SCARRY",
    PcodeOp.LOAD: "LOAD", PcodeOp.STORE: "STORE",
    PcodeOp.BRANCH: "BRANCH", PcodeOp.CBRANCH: "CBRANCH",
    PcodeOp.CALL: "CALL", PcodeOp.RETURN: "RETURN",
    PcodeOp.MULTIEQUAL: "PHI" 
}

# =============================================================================
# 2. HELPER FUNCTIONS
# =============================================================================

def calculate_entropy(data_bytes):
    """Calculates Shannon Entropy of a list of byte values."""
    if not data_bytes: return 0.0
    entropy = 0
    length = len(data_bytes)
    counts = {}
    for b in data_bytes:
        counts[b] = counts.get(b, 0) + 1
    
    for count in counts.values():
        p_x = float(count) / length
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def get_tarjan_scc(graph_nodes, graph_edges):
    """
    Computes Strongly Connected Components (SCC) count.
    Useful for detecting complex state machines vs simple loops.
    """
    index_counter = [0]
    stack = []
    lowlink = {}
    index = {}
    result = []
    
    def connect(node):
        index[node] = index_counter[0]
        lowlink[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        
        successors = graph_edges.get(node, [])
        for successor in successors:
            if successor not in index:
                connect(successor)
                lowlink[node] = min(lowlink[node], lowlink[successor])
            elif successor in stack:
                lowlink[node] = min(lowlink[node], index[successor])
        
        if lowlink[node] == index[node]:
            connected_component = []
            while True:
                successor = stack.pop()
                connected_component.append(successor)
                if successor == node: break
            result.append(connected_component)
            
    for node in graph_nodes:
        if node not in index:
            connect(node)
            
    return len(result)

def detect_crypto_signatures(func, immediates):
    signatures = {
        "has_aes_sbox": 0,
        "has_aes_rcon": 0,
        "has_sha_constants": 0,
        "rsa_bigint_detected": 0,
        "has_chacha_constants": 0
    }
    # Check immediates against CRYPTO_CONSTANTS
    for val in immediates:
        val32 = val & 0xFFFFFFFF
        if val32 in CRYPTO_CONSTANTS.get("AES_SBOX", []) or val32 in CRYPTO_CONSTANTS.get("AES_SBOX_BYTES", []):
            signatures["has_aes_sbox"] = 1
        if val32 in CRYPTO_CONSTANTS.get("AES_RCON", []):
            signatures["has_aes_rcon"] = 1
        if val32 in CRYPTO_CONSTANTS.get("SHA1_K", []) or val32 in CRYPTO_CONSTANTS.get("SHA256_K", []):
            signatures["has_sha_constants"] = 1
        if val32 in CRYPTO_CONSTANTS.get("P256_PRIME", []) or val32 in CRYPTO_CONSTANTS.get("C25519_PRIME", []):
             signatures["rsa_bigint_detected"] = 1
        if val32 in CRYPTO_CONSTANTS.get("CHACHA_SIG", []):
             signatures["has_chacha_constants"] = 1
    return signatures

def calculate_function_entropy_metrics(func, opcode_list, cyclomatic_complexity, total_inst_count, current_program):
    metrics = {
        "function_byte_entropy": 0.0,
        "opcode_entropy": 0.0,
        "cyclomatic_complexity_density": 0.0
    }
    
    # Byte entropy
    try:
        data_bytes = []
        listing = current_program.getListing()
        code_units = listing.getCodeUnits(func.getBody(), True)
        while code_units.hasNext():
            cu = code_units.next()
            try:
                b = cu.getBytes()
                data_bytes.extend([x & 0xFF for x in b])
            except:
                pass
        
        if data_bytes:
            metrics["function_byte_entropy"] = calculate_entropy(data_bytes)
    except:
        pass


    # Opcode entropy
    if opcode_list:
        metrics["opcode_entropy"] = calculate_entropy(opcode_list)

    if total_inst_count > 0:
        metrics["cyclomatic_complexity_density"] = float(cyclomatic_complexity) / total_inst_count
        
    return metrics

def extract_instruction_ngrams(instruction_mnemonics):
    if len(instruction_mnemonics) < 2:
        return {"top_5_bigrams": [], "unique_ngram_count": 0}
    
    bigrams = []
    for i in range(len(instruction_mnemonics) - 1):
        bigram = "{} {}".format(instruction_mnemonics[i], instruction_mnemonics[i+1])
        bigrams.append(bigram)
        
    counts = {}
    for bg in bigrams:
        counts[bg] = counts.get(bg, 0) + 1
        
    sorted_bigrams = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    top_5 = [bg[0] for bg in sorted_bigrams[:5]]
    
    return {
        "top_5_bigrams": top_5,
        "unique_ngram_count": len(counts)
    }

def analyze_data_references(func, current_program):
    refs = {
        "string_refs_count": 0,
        "rodata_refs_count": 0,
        "stack_frame_size": func.getStackFrame().getFrameSize()
    }
    
    # Iterate instructions in the function
    inst_iter = current_program.getListing().getInstructions(func.getBody(), True)
    while inst_iter.hasNext():
        inst = inst_iter.next()
        # Get references from this instruction
        for ref in inst.getReferencesFrom():
            if ref.isMemoryReference():
                to_addr = ref.getToAddress()
                block = current_program.getMemory().getBlock(to_addr)
                if block:
                    name = block.getName()
                    # Check for Read-Only Data (Initialized, Not Executable, Not Writable)
                    if block.isInitialized() and not block.isExecute() and not block.isWrite():
                        refs["rodata_refs_count"] += 1
                    elif ".rodata" in name or ".const" in name:
                        refs["rodata_refs_count"] += 1
                    # Simple string check could be added here if needed
                
    return refs

def categorize_operations(pcode_ops):
    counts = {
        "arithmetic_ops": 0,
        "bitwise_ops": 0,
        "crypto_like_ops": 0,
        "mem_ops_ratio": 0.0,
        "add_ratio": 0.0,
        "logical_ratio": 0.0,
        "load_store_ratio": 0.0,
        "xor_ratio": 0.0,
        "multiply_ratio": 0.0,
        "rotate_ratio": 0.0
    }
    total = 0
    ops_counts = {"ADD": 0, "LOGIC": 0, "MEM": 0, "XOR": 0, "MUL": 0, "ROT": 0}
    
    for op in pcode_ops:
        total += 1
        opcode = op.getOpcode()
        if opcode in [PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, PcodeOp.INT_DIV, PcodeOp.INT_REM]:
            counts["arithmetic_ops"] += 1
        elif opcode in [PcodeOp.INT_XOR, PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT]:
            counts["bitwise_ops"] += 1
        
        if opcode in [PcodeOp.INT_XOR, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT]:
             counts["crypto_like_ops"] += 1
             
        # Ratio counting
        if opcode == PcodeOp.INT_ADD: ops_counts["ADD"] += 1
        if opcode in [PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR]: ops_counts["LOGIC"] += 1
        if opcode in [PcodeOp.LOAD, PcodeOp.STORE]: ops_counts["MEM"] += 1
        if opcode == PcodeOp.INT_XOR: ops_counts["XOR"] += 1
        if opcode == PcodeOp.INT_MULT: ops_counts["MUL"] += 1
        if opcode in [PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT]: ops_counts["ROT"] += 1
             
    if total > 0:
        mem_ops = sum(1 for op in pcode_ops if op.getOpcode() in [PcodeOp.LOAD, PcodeOp.STORE])
        counts["mem_ops_ratio"] = float(mem_ops) / total
        
        counts["add_ratio"] = float(ops_counts["ADD"]) / total
        counts["logical_ratio"] = float(ops_counts["LOGIC"]) / total
        counts["load_store_ratio"] = float(ops_counts["MEM"]) / total
        counts["xor_ratio"] = float(ops_counts["XOR"]) / total
        counts["multiply_ratio"] = float(ops_counts["MUL"]) / total
        counts["rotate_ratio"] = float(ops_counts["ROT"]) / total
        
    return counts

def calculate_loop_depth(all_nodes, back_edges, pred_list):
    if not back_edges:
        return 0
        
    loops = []
    for src, header in back_edges:
        loop_nodes = set([header, src])
        stack = [src]
        while stack:
            curr = stack.pop()
            for pred in pred_list.get(curr, []):
                if pred not in loop_nodes:
                    loop_nodes.add(pred)
                    stack.append(pred)
        loops.append(loop_nodes)
        
    max_depth = 0
    for node in all_nodes:
        depth = sum(1 for loop in loops if node in loop)
        if depth > max_depth:
            max_depth = depth
            
    return max_depth



# =============================================================================
    for item in data:
        counts[item] = counts.get(item, 0) + 1
    for count in counts.values():
        p = float(count) / length
        entropy -= p * math.log(p, 2)
    return entropy

def extract_graph_features(func):
    """Extracts structural features: Complexity, Loops, SCCs."""
    model = BasicBlockModel(currentProgram)
    blocks = model.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)
    
    num_blocks = 0
    num_edges = 0
    back_edges = 0 # Loop count approximation
    
    # Simple CFG traversal
    visited = set()
    
    # We need to iterate to count blocks and edges
    # Note: getCodeBlocksContaining returns a CodeBlockIterator
    
    # Create a list of blocks first to avoid iterator exhaustion issues if reused
    block_list = []
    while blocks.hasNext():
        block_list.append(blocks.next())
    
    num_blocks = len(block_list)
    
    for block in block_list:
        destinations = block.getDestinations(TaskMonitor.DUMMY)
        while destinations.hasNext():
            edge = destinations.next()
            num_edges += 1
            dest_addr = edge.getDestinationAddress()
            
            # Check for back-edge (destination address < source address)
            # This is a heuristic for loops
            if dest_addr.compareTo(block.getFirstStartAddress()) < 0:
                back_edges += 1

    # Cyclomatic Complexity: E - N + 2P (P=1 for single function)
    cyclomatic_complexity = num_edges - num_blocks + 2
    
    return {
        "cyclomatic_complexity": cyclomatic_complexity,
        "loop_count": back_edges,
        "num_blocks": num_blocks,
        "num_edges": num_edges
    }

def extract_node_features(func):
    """Extracts semantic features from P-Code."""
    
    # Counters
    opcode_counts = {
        "INT_XOR": 0, "INT_AND": 0, "INT_OR": 0, "INT_ADD": 0, "INT_SUB": 0,
        "INT_MULT": 0, "INT_LEFT": 0, "INT_RIGHT": 0, "INT_SRIGHT": 0,
        "COPY": 0, "LOAD": 0, "STORE": 0, "CALL": 0, "BRANCH": 0
    }
    
    total_ops = 0
    bitwise_ops = 0
    immediates = []
    # Resilience: N-Grams (3-gram)
    pcode_sequence = []
    ngram_counts = {}
    
    # Resilience: Carry Chains
    carry_chain_depth = 0
    current_chain = 0
    
    # Constant Matching
    detected_constants = set()

    ops_iter = get_pcode_ops(func)
    
    for op in ops_iter:
        mnemonic = op.getMnemonic()
        total_ops += 1
        
        # 1. Opcode Counts
        if mnemonic in opcode_counts:
            opcode_counts[mnemonic] += 1
            
        # 2. Bitwise Density
        if mnemonic in ["INT_XOR", "INT_AND", "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT"]:
            bitwise_ops += 1
            
        # 3. Immediates & Constants
        for input_var in op.getInputs():
            if input_var.isConstant():
                val = input_var.getOffset()
                immediates.append(val)
                
                # Check against known crypto constants
                # We check 32-bit chunks for speed
                val32 = val & 0xFFFFFFFF
                for algo, consts in CRYPTO_CONSTANTS.items():
                    if val32 in consts:
                        detected_constants.add(algo)

        # 4. N-Grams (Sliding Window of 3)
        pcode_sequence.append(mnemonic)
        if len(pcode_sequence) > 3:
            pcode_sequence.pop(0)
        
        if len(pcode_sequence) == 3:
            ngram = tuple(pcode_sequence)
            ngram_counts[ngram] = ngram_counts.get(ngram, 0) + 1

        # 5. Carry Chains (Heuristic)
        # INT_CARRY and INT_SCARRY often precede INT_ADD in big int math
        if mnemonic in ["INT_CARRY", "INT_SCARRY"]:
            current_chain += 1
        elif mnemonic not in ["INT_ADD", "COPY"]:
            # Break chain on non-arithmetic ops
            if current_chain > carry_chain_depth:
                carry_chain_depth = current_chain
            current_chain = 0

    # Finalize Features
    bitwise_density = float(bitwise_ops) / total_ops if total_ops > 0 else 0.0
    
    # Find most frequent N-Gram
    most_frequent_ngram_count = 0
    if ngram_counts:
        most_frequent_ngram_count = max(ngram_counts.values())
    
    # Normalize N-Gram repetition
    ngram_repetition = float(most_frequent_ngram_count) / total_ops if total_ops > 0 else 0.0

    # Statistical Immediates
    imm_min = min(immediates) if immediates else 0
    imm_max = max(immediates) if immediates else 0
    imm_entropy = calculate_entropy(immediates)

    return {
        "bitwise_density": bitwise_density,
        "memory_stride": 0, # Placeholder for advanced stride analysis
        "n_gram_repetition": ngram_repetition,
        "carry_chain_depth": carry_chain_depth,
        "imm_entropy": imm_entropy,
        "detected_constants": list(detected_constants)
    }

def run_analysis():
    """Main analysis loop."""
    program_name = currentProgram.getName()
    
    # Metadata Extraction
    lang = currentProgram.getLanguage()
    arch_str = lang.getProcessor().toString()
    endian_str = "little" if lang.isBigEndian() == False else "big"
    bit_size_int = lang.getDefaultSpace().getPointerSize() * 8
    
    metadata = {
        "filename": program_name,
        "compiler_id": currentProgram.getCompilerSpec().getCompilerByID().toString()
    }
    
    output_data = {
        "metadata": metadata,
        "functions": []
    }
    
    print("Starting Feature Extraction for: " + program_name)
    print("Arch: {} ({}-bit {})".format(arch_str, bit_size_int, endian_str))
    
    func_iter = currentProgram.getFunctionManager().getFunctions(True)
    for func in func_iter:
        # Skip stubs
        if func.getBody().getNumAddresses() < 20:
            continue
            
        f_name = func.getName()
        f_addr = func.getEntryPoint().toString()
        
        try:
            # Layer A: Structure
            graph_feats = extract_graph_features(func)
            
            # Layer B & C: Semantics & Resilience
            node_feats = extract_node_features(func)
            
            # Combine
            func_entry = {
                "name": f_name,
                "address": f_addr,
                "arch": arch_str,
                "endian": endian_str,
                "bit_size": bit_size_int,
                "graph_features": graph_feats,
                "node_features": [
                    node_feats["bitwise_density"],
                    node_feats["n_gram_repetition"],
                    node_feats["carry_chain_depth"],
                    node_feats["imm_entropy"]
                ],
                "constant_hits": node_feats["detected_constants"]
            }
            
            output_data["functions"].append(func_entry)
            
        except Exception as e:
            print("Error analyzing function {}: {}".format(f_name, e))

    # Save Output
    output_file = program_name + "_features.json"
    # Get directory of current program if possible, else use current dir
    # In Headless, usually writes to CWD
    
    print("Saving results to: " + output_file)
    with open(output_file, "w") as f:
        json.dump(output_data, f, indent=4)

if __name__ == "__main__":
    run_analysis()
    # N-Gram Repetition (Unrolled Loop Detector)
    if len(raw_opcodes) >= 6:
        trigrams = []
        for i in range(len(raw_opcodes) - 2):
            trigrams.append(tuple(raw_opcodes[i:i+3]))
        if trigrams:
            most_common = max(set(trigrams), key=trigrams.count)
            freq = trigrams.count(most_common)
            # Score: How much of the block is composed of the repeating pattern?
            features["n_gram_repetition"] = float(freq * 3) / len(raw_opcodes)

    return features

def extract_advanced_features(func, current_program, node_features):
    """
    Extracts high-level algorithmic features based on aggregated node data.
    """
    adv_features = {
        # AES
        "has_aes_sbox": False, "aes_sbox_match_score": 0.0, "has_aes_rcon": False,
        "tbox_detected": False, "gf256_mul_ratio": 0.0, "mixcolumns_pattern_score": 0.0,
        "key_expansion_detection": False, "num_large_tables": 0, "table_entropy_score": 0.0,
        "approx_rounds": 0,
        
        # RSA
        "bigint_op_count": 0, "montgomery_op_count": 0, "modexp_op_density": 0.0,
        "exponent_bit_length": 0, "modulus_bit_length": 0, "bigint_width": 0,
        "bignum_limb_count": 0,
        
        # ECC
        "curve25519_constant_detection": False, "ladder_step_count": 0,
        "cswap_patterns": 0, "projective_affine_ops_count": 0, "mixed_coordinate_ratio": 0.0,
        
        # SHA
        "sha_init_constants_hits": 0, "sha_k_table_hits": 0, "sha_rotation_patterns": 0,
        "schedule_size_detection": 0, "bitwise_mix_operations": 0,
        
        # PRNG
        "lcg_multiplier": 0, "lcg_increment": 0, "lcg_mod": 0,
        "mt19937_constants": False, "quarterround_score": 0, "feedback_polynomial": 0,
        "has_chacha_constants": False,
        
        # General
        "string_refs_count": 0, "rodata_refs_count": 0, "data_refs_count": 0,
        "stack_frame_size": func.getStackFrame().getFrameSize(),
        "string_density": 0.0, "call_in_degree": 0, "call_out_degree": 0,
        "betweenness_centrality": 0.0, "pagerank_score": 0.0
    }

    # Aggregated Counters
    total_inst = 0
    total_xor = 0
    total_rot = 0
    
    # 1. Aggregate Node Data
    for nf in node_features:
        total_inst += nf["instruction_count"]
        total_xor += nf["opcode_histogram"].get("XOR", 0)
        # Fix: Sum specific shift/rotate mnemonics
        rot_count = nf["opcode_histogram"].get("SHL", 0) + \
                    nf["opcode_histogram"].get("SHR", 0) + \
                    nf["opcode_histogram"].get("SAR", 0)
        total_rot += rot_count
        
        # AES Checks
        if nf["constant_flags"].get("AES_SBOX", False) or nf["constant_flags"].get("AES_INV_SBOX", False):
            adv_features["has_aes_sbox"] = True
            adv_features["aes_sbox_match_score"] += 1.0
        if nf["constant_flags"].get("AES_RCON", False):
            adv_features["has_aes_rcon"] = True
            adv_features["key_expansion_detection"] = True
        if nf["constant_flags"].get("AES_TE0", False):
            adv_features["tbox_detected"] = True
            
        # AES MixColumns / GF(2^8) Heuristics
        # Look for "xtime" pattern: (x << 1) ^ ((x >> 7) & 1 ? 0x1b : 0)
        # Simplified: Check for shifts and XORs with 0x1b
        if 0x1b in nf.get("immediates", []): # Need to ensure immediates are passed up or check entropy
             adv_features["gf256_mul_ratio"] += 1.0
             adv_features["mixcolumns_pattern_score"] += 1.0

        # SHA Checks
        if nf["constant_flags"].get("SHA1_INIT", False) or nf["constant_flags"].get("SHA256_INIT", False) or nf["constant_flags"].get("SHA224_INIT", False):
            adv_features["sha_init_constants_hits"] += 1
        if nf["constant_flags"].get("SHA1_K", False) or nf["constant_flags"].get("SHA256_K", False):
            adv_features["sha_k_table_hits"] += 1
            
        # ECC Checks
        if nf["constant_flags"].get("P256_PRIME", False) or nf["constant_flags"].get("C25519_PRIME", False):
            adv_features["curve25519_constant_detection"] = True
            
        # PRNG Checks
        if nf["constant_flags"].get("MT19937_MATRIX_A", False):
            adv_features["mt19937_constants"] = True
            
        if nf["constant_flags"].get("CHACHA_SIG", False):
            adv_features["has_chacha_constants"] = True
            
        # BigInt / RSA Heuristics
        if nf["carry_chain_depth"] > 2:
            adv_features["bigint_op_count"] += 1
            adv_features["bigint_width"] = max(adv_features["bigint_width"], nf["carry_chain_depth"] * 32) # Approx
            
        # Table Analysis
        if nf["table_lookup_presence"]:
            adv_features["num_large_tables"] += 1
            adv_features["table_entropy_score"] += nf["immediate_entropy"]
            
        # ModExp / Montgomery Heuristics (High MUL/DIV density)
        mul_count = nf["opcode_histogram"].get("MUL", 0)
        div_count = nf["opcode_histogram"].get("DIV", 0) + nf["opcode_histogram"].get("MOD", 0)
        if mul_count > 0 and div_count > 0:
             adv_features["modexp_op_density"] += (mul_count + div_count)
             
        # SHA Rotation Patterns (High Rotate density)
        if rot_count > 2:
            adv_features["sha_rotation_patterns"] += 1
            
        # Bitwise Mix (XOR + ROT)
        if (nf["opcode_histogram"].get("XOR", 0) + rot_count) > 5:
            adv_features["bitwise_mix_operations"] += 1
            
        # Ladder Step / CSWAP (Conditional Branch + Swap logic)
        # Heuristic: Branch followed by PHI or CMOV-like logic (hard to detect perfectly in aggregated stats)
        if nf["opcode_histogram"].get("PHI", 0) > 0 and nf["opcode_histogram"].get("CBRANCH", 0) > 0:
            adv_features["cswap_patterns"] += 1
            adv_features["ladder_step_count"] += 1

    # 2. Call Graph Metrics (Local)
    refs = current_program.getReferenceManager().getReferencesTo(func.getEntryPoint())
    adv_features["call_in_degree"] = sum(1 for r in refs if r.getReferenceType().isCall())
    
    # Calculate Out-Degree
    # We can iterate the function body and count CALL instructions
    out_degree = 0
    listing = current_program.getListing()
    code_units = listing.getCodeUnits(func.getBody(), True)
    while code_units.hasNext():
        cu = code_units.next()
        if cu.getMnemonicString() == "CALL":
            out_degree += 1
    adv_features["call_out_degree"] = out_degree

    # Normalize Densities
    if total_inst > 0:
        adv_features["modexp_op_density"] /= total_inst
        adv_features["string_density"] = float(adv_features["string_refs_count"]) / total_inst
        adv_features["gf256_mul_ratio"] /= total_inst
        
    # Schedule Size Detection (Heuristic based on loop count and block size)
    # SHA schedule often involves a loop of 64/80 iterations expanding data
    # We can infer from total_inst if it's a massive unrolled block.
    if total_inst > 500 and adv_features["bitwise_mix_operations"] > 10:
        adv_features["schedule_size_detection"] = 1 # Likely unrolled schedule
        
    # Approx Rounds (AES)
    # If we detected Rcon, count how many unique Rcon constants we saw?
    # Or just use instruction count / 100 as a rough proxy if AES detected
    if adv_features["has_aes_rcon"] or adv_features["has_aes_sbox"]:
        adv_features["approx_rounds"] = int(total_inst / 16) # Very rough heuristic

    return adv_features


def extract_function_data(func, current_program):
    """
    Orchestrates features for a whole function.
    """
    func_name = func.getName()
    label = "Non-Crypto"
    
    # Labeling Logic
    func_lower = func_name.lower()
    for key, val in LABEL_MAP.items():
        if key.lower() in func_lower:
            label = val
            break

    func_data = {
        "name": func_name,
        "address": func.getEntryPoint().toString(),
        "label": label, 
        "graph_level": {},
        "node_level": [],
        "edge_level": []
    }
    
    block_model = BasicBlockModel(current_program)
    blocks = block_model.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)
    
    node_ids = []
    adj_list = {}
    pred_list = {}
    back_edges = []
    
    num_blocks = 0
    num_edges = 0
    loop_count = 0
    loop_edges = 0
    entries = 0
    exits = 0
    num_conditional_edges = 0
    num_unconditional_edges = 0
    total_branch_complexity = 0
    
    # Function-wide data collection
    all_immediates = []
    all_instruction_mnemonics = []
    all_pcode_ops = []
    all_opcode_mnemonics = []

    
    # Iterate Blocks
    while blocks.hasNext():
        bb = blocks.next()
        num_blocks += 1
        bb_addr = bb.getMinAddress().toString()
        node_ids.append(bb_addr)
        
        # 1. Node Features
        node_feats = extract_node_features(bb, current_program.getListing())
        node_feats["address"] = bb_addr
        func_data["node_level"].append(node_feats)
        
        if "immediates" in node_feats:
            all_immediates.extend(node_feats["immediates"])
            
        # Collect function-wide data
        inst_iter = currentProgram.getListing().getInstructions(bb, True)
        while inst_iter.hasNext():
            inst = inst_iter.next()
            all_instruction_mnemonics.append(inst.getMnemonicString().lower())
            
            for op in inst.getPcode():
                all_pcode_ops.append(op)
                all_opcode_mnemonics.append(PCODE_MAP.get(op.getOpcode(), "OTHER"))

        
        # 2. Edges
        destinations = bb.getDestinations(TaskMonitor.DUMMY)
        has_successor = False
        
        while destinations.hasNext():
            has_successor = True
            ref = destinations.next()
            num_edges += 1
            dst_addr = ref.getDestinationAddress().toString()
            
            if bb_addr not in adj_list: adj_list[bb_addr] = []
            adj_list[bb_addr].append(dst_addr)
            
            if dst_addr not in pred_list: pred_list[dst_addr] = []
            pred_list[dst_addr].append(bb_addr)
            
            # Loop Detection (Back Edge)
            is_loop = ref.getDestinationAddress().compareTo(bb.getMinAddress()) < 0
            if is_loop: 
                loop_count += 1
                loop_edges += 1
                back_edges.append((bb_addr, dst_addr))
            
            # Branch Complexity
            branch_complexity = 0
            flow_type = ref.getFlowType()
            if flow_type.isConditional():
                 num_conditional_edges += 1
            else:
                 num_unconditional_edges += 1
            if flow_type.isConditional():
                 # Heuristic: Count logic ops in source block
                 branch_complexity = node_feats["opcode_histogram"].get("AND", 0) + \
                                     node_feats["opcode_histogram"].get("OR", 0) + \
                                     node_feats["opcode_histogram"].get("XOR", 0)
            total_branch_complexity += branch_complexity

            func_data["edge_level"].append({
                "src": bb_addr,
                "dst": dst_addr,
                "edge_type": "conditional" if flow_type.isConditional() else "unconditional",
                "is_loop_edge": is_loop,
                "branch_condition_complexity": branch_complexity
            })

        if bb.getSources(TaskMonitor.DUMMY).hasNext() == False:
            entries += 1
        if not has_successor:
            exits += 1

    # 3. Graph Level Features
    func_data["graph_level"] = {
        "num_basic_blocks": num_blocks,
        "num_edges": num_edges,
        "num_conditional_edges": num_conditional_edges,
        "num_unconditional_edges": num_unconditional_edges,
        "num_loop_edges": loop_edges,
        "avg_edge_branch_condition_complexity": float(total_branch_complexity) / num_edges if num_edges > 0 else 0.0,
        "cyclomatic_complexity": num_edges - num_blocks + 2,
        "loop_count": loop_count,
        "loop_depth": calculate_loop_depth(node_ids, back_edges, pred_list),
        "branch_density": float(loop_edges) / num_edges if num_edges > 0 else 0.0,
        "average_block_size": sum(n["instruction_count"] for n in func_data["node_level"]) / float(num_blocks) if num_blocks > 0 else 0,
        "num_entry_exit_paths": entries + exits,
        "strongly_connected_components": get_tarjan_scc(node_ids, adj_list)
    }
    
    # 4. Advanced Algorithmic Features
    adv_feats = extract_advanced_features(func, current_program, func_data["node_level"])
    func_data["advanced_features"] = adv_feats
    
    # 5. New Comprehensive Features
    crypto_sigs = detect_crypto_signatures(func, all_immediates)
    
    total_inst = sum(n["instruction_count"] for n in func_data["node_level"])
    entropy_metrics = calculate_function_entropy_metrics(func, all_opcode_mnemonics, func_data["graph_level"]["cyclomatic_complexity"], total_inst, current_program)

    instruction_seq = extract_instruction_ngrams(all_instruction_mnemonics)
    data_refs = analyze_data_references(func, current_program)
    op_counts = categorize_operations(all_pcode_ops)
    
    func_data["crypto_signatures"] = crypto_sigs
    func_data["entropy_metrics"] = entropy_metrics
    func_data["instruction_sequence"] = instruction_seq
    func_data["data_references"] = data_refs
    func_data["op_category_counts"] = op_counts

    
    return func_data

# =============================================================================
# 4. MAIN EXECUTION
# =============================================================================

def run_analysis():
    program_name = currentProgram.getName()
    print("[*] Starting Vestigo Analysis on: " + program_name)
    
    output_data = {
        "binary": program_name,
        "metadata": {
            "text_size": 0,
            "rodata_size": 0,
            "data_size": 0,
            "num_functions": 0,
            "total_tables_detected": 0
        },
        "functions": []
    }
    
    # Extract Section Sizes
    mem = currentProgram.getMemory()
    for block in mem.getBlocks():
        name = block.getName()
        size = block.getSize()
        if ".text" in name:
            output_data["metadata"]["text_size"] += size
        elif ".rodata" in name:
            output_data["metadata"]["rodata_size"] += size
        elif ".data" in name:
            output_data["metadata"]["data_size"] += size

    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    
    for f in funcs:
        # Filter out tiny stubs
        if f.getBody().getNumAddresses() < 10:
            continue
            
        try:
            f_data = extract_function_data(f, currentProgram)
            output_data["functions"].append(f_data)
            output_data["metadata"]["total_tables_detected"] += f_data["advanced_features"]["num_large_tables"]
        except Exception as e:
            print("Error analyzing {}: {}".format(f.getName(), e))
            
    output_data["metadata"]["num_functions"] = len(output_data["functions"])
            
    # Save JSON to same directory as binary
    args = getScriptArgs()
    # Default to current working directory if no arg
    project_root = args[0] if len(args) > 0 else "."
    # Save to ghidra_json    directory
    output_dir = os.path.join(project_root, "ghidra_json")
    # output_dir = os.path.join(project_root, "ghidra_output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    output_file = os.path.join(output_dir, "{}_features.json".format(program_name))
    
    print("[*] Saving features to: {}".format(output_file))
    
    with open(output_file, "w") as f:
        json.dump(output_data, f, indent=4)

if __name__ == "__main__":
    run_analysis()

