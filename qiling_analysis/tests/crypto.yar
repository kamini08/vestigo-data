/*
    Crypto Detection YARA Rules
    High-quality ruleset for detecting cryptographic constants in binaries.
    Based on FindCrypt logic - detects S-boxes, IVs, round constants, magic numbers.
    Works on stripped, obfuscated, and firmware binaries.
*/

// ======================== AES/Rijndael ========================

rule AES_Sbox {
    meta:
        description = "AES/Rijndael Forward S-Box"
        author = "CryptoDetect"
        algorithm = "AES"
        confidence = 95
    strings:
        // Complete AES S-Box (256 bytes)
        $sbox = {
            63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
            CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
            B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15
            04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75
            09 83 2C 1A 1B 6E 5A A0 52 3B D6 B3 29 E3 2F 84
            53 D1 00 ED 20 FC B1 5B 6A CB BE 39 4A 4C 58 CF
            D0 EF AA FB 43 4D 33 85 45 F9 02 7F 50 3C 9F A8
            51 A3 40 8F 92 9D 38 F5 BC B6 DA 21 10 FF F3 D2
            CD 0C 13 EC 5F 97 44 17 C4 A7 7E 3D 64 5D 19 73
            60 81 4F DC 22 2A 90 88 46 EE B8 14 DE 5E 0B DB
            E0 32 3A 0A 49 06 24 5C C2 D3 AC 62 91 95 E4 79
            E7 C8 37 6D 8D D5 4E A9 6C 56 F4 EA 65 7A AE 08
            BA 78 25 2E 1C A6 B4 C6 E8 DD 74 1F 4B BD 8B 8A
            70 3E B5 66 48 03 F6 0E 61 35 57 B9 86 C1 1D 9E
            E1 F8 98 11 69 D9 8E 94 9B 1E 87 E9 CE 55 28 DF
            8C A1 89 0D BF E6 42 68 41 99 2D 0F B0 54 BB 16
        }
        
        // Partial S-Box (first 64 bytes for obfuscated versions)
        $sbox_partial = {
            63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
            CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
            B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15
            04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75
        }
    condition:
        any of them
}

rule AES_InvSbox {
    meta:
        description = "AES/Rijndael Inverse S-Box"
        author = "CryptoDetect"
        algorithm = "AES"
        confidence = 95
    strings:
        $inv_sbox = {
            52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB
            7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB
            54 7B 94 32 A6 C2 23 3D EE 4C 95 0B 42 FA C3 4E
            08 2E A1 66 28 D9 24 B2 76 5B A2 49 6D 8B D1 25
            72 F8 F6 64 86 68 98 16 D4 A4 5C CC 5D 65 B6 92
            6C 70 48 50 FD ED B9 DA 5E 15 46 57 A7 8D 9D 84
            90 D8 AB 00 8C BC D3 0A F7 E4 58 05 B8 B3 45 06
            D0 2C 1E 8F CA 3F 0F 02 C1 AF BD 03 01 13 8A 6B
        }
    condition:
        $inv_sbox
}

rule AES_Rcon {
    meta:
        description = "AES Round Constants (Key Expansion)"
        author = "CryptoDetect"
        algorithm = "AES"
        confidence = 90
    strings:
        // Rcon values used in AES key expansion
        $rcon = { 01 02 04 08 10 20 40 80 1B 36 }
        
        // Extended Rcon (with 00 padding as appears in implementations)
        $rcon_ext = { 00 01 02 04 08 10 20 40 80 1B 36 }
    condition:
        any of them
}

rule AES_TE_Tables {
    meta:
        description = "AES T-tables (TE0-TE3) for optimized implementation"
        author = "CryptoDetect"
        algorithm = "AES"
        confidence = 85
    strings:
        // TE0 table first entries (used in fast AES implementations)
        $te0 = { C6 63 63 A5 F8 7C 7C 84 }
        $te1 = { A5 C6 63 63 84 F8 7C 7C }
        $te2 = { 63 A5 C6 63 7C 84 F8 7C }
        $te3 = { 63 63 A5 C6 7C 7C 84 F8 }
    condition:
        any of them
}

// ======================== DES ========================

rule DES_Sboxes {
    meta:
        description = "DES S-Boxes"
        author = "CryptoDetect"
        algorithm = "DES/3DES"
        confidence = 95
    strings:
        // DES S-Box 1
        $sbox1 = {
            0E 04 0D 01 02 0F 0B 08 03 0A 06 0C 05 09 00 07
            00 0F 07 04 0E 02 0D 01 0A 06 0C 0B 09 05 03 08
        }
        
        // DES Initial Permutation (IP)
        $ip = {
            3A 32 2A 22 1A 12 0A 02 3C 34 2C 24 1C 14 0C 04
            3E 36 2E 26 1E 16 0E 06 40 38 30 28 20 18 10 08
        }
    condition:
        any of them
}

// ======================== SHA Family ========================

rule SHA1_Constants {
    meta:
        description = "SHA-1 Initialization Vector and Constants"
        author = "CryptoDetect"
        algorithm = "SHA-1"
        confidence = 95
    strings:
        // SHA-1 IV (H0-H4) in big-endian
        $h_be = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 C3 D2 E1 F0 }
        
        // SHA-1 IV in little-endian
        $h_le = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 F0 E1 D2 C3 }
        
        // SHA-1 Round Constants
        $k1 = { 5A 82 79 99 }  // K1 = 0x5A827999
        $k2 = { 6E D9 EB A1 }  // K2 = 0x6ED9EBA1
        $k3 = { 8F 1B BC DC }  // K3 = 0x8F1BBCDC
        $k4 = { CA 62 C1 D6 }  // K4 = 0xCA62C1D6
    condition:
        any of them
}

rule SHA256_Constants {
    meta:
        description = "SHA-256 Initial Hash Values and Round Constants"
        author = "CryptoDetect"
        algorithm = "SHA-256"
        confidence = 95
    strings:
        // SHA-256 IV (H0-H7) in big-endian
        $h_be = {
            6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A
            51 0E 52 7F 9B 05 68 8C 1F 83 D9 AB 5B E0 CD 19
        }
        
        // First 8 K constants (out of 64)
        $k_start = {
            42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5
            39 56 C2 5B 59 F1 11 F1 92 3F 82 A4 AB 1C 5E D5
        }
    condition:
        any of them
}

rule SHA512_Constants {
    meta:
        description = "SHA-512 Initial Hash Values"
        author = "CryptoDetect"
        algorithm = "SHA-512"
        confidence = 95
    strings:
        // SHA-512 IV (H0-H7) in big-endian (first 32 bytes)
        $h_be = {
            6A 09 E6 67 F3 BC C9 08 BB 67 AE 85 84 CA A7 3B
            3C 6E F3 72 FE 94 F8 2B A5 4F F5 3A 5F 1D 36 F1
        }
    condition:
        $h_be
}

// ======================== MD5 ========================

rule MD5_Constants {
    meta:
        description = "MD5 Initialization Vector and Constants"
        author = "CryptoDetect"
        algorithm = "MD5"
        confidence = 95
    strings:
        // MD5 IV in little-endian
        $iv_le = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
        
        // MD5 IV in big-endian (some implementations)
        $iv_be = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 }
        
        // First 4 T constants (out of 64)
        $t_start = { D7 6A A4 78 E8 C7 B7 56 42 70 DB 20 C1 BD CE EE }
    condition:
        any of them
}

// ======================== ChaCha20 / Salsa20 ========================

rule ChaCha20_Constants {
    meta:
        description = "ChaCha20 Magic Constants"
        author = "CryptoDetect"
        algorithm = "ChaCha20"
        confidence = 100
    strings:
        // "expand 32-byte k" in little-endian
        $magic_le = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
        
        // In some implementations it might be split or aligned differently
        $magic_ascii = "expand 32-byte k"
        
        // "expand 16-byte k" for ChaCha20-256
        $magic16_le = { 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B }
    condition:
        any of them
}

rule Salsa20_Constants {
    meta:
        description = "Salsa20 Magic Constants"
        author = "CryptoDetect"
        algorithm = "Salsa20"
        confidence = 100
    strings:
        // "expand 32-byte k"
        $magic32 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
        
        // "expand 16-byte k"
        $magic16 = { 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B }
    condition:
        any of them
}

// ======================== RC4 ========================

rule RC4_Identity_Permutation {
    meta:
        description = "RC4 Identity Permutation Initialization"
        author = "CryptoDetect"
        algorithm = "RC4/ARC4"
        confidence = 85
    strings:
        // First 32 bytes of identity permutation (0x00-0x1F)
        $identity = {
            00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
            10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
        }
    condition:
        $identity
}

// ======================== Blowfish ========================

rule Blowfish_PArray {
    meta:
        description = "Blowfish P-Array Initial Values"
        author = "CryptoDetect"
        algorithm = "Blowfish"
        confidence = 95
    strings:
        // First 4 P-array values (derived from digits of Pi)
        $parray = { 24 3F 6A 88 85 A3 08 D3 13 19 8A 2E 03 70 73 44 }
    condition:
        $parray
}

// ======================== Camellia ========================

rule Camellia_Sbox {
    meta:
        description = "Camellia S-Box"
        author = "CryptoDetect"
        algorithm = "Camellia"
        confidence = 90
    strings:
        // Camellia SBOX1
        $sbox1 = {
            70 82 2C EC 94 27 C9 5A 9D C3 D5 21 79 37 F6 B7
            8B DC F2 B3 A8 50 70 82 2C EC 94 27 C9 5A 9D C3
        }
    condition:
        $sbox1
}

// ======================== RSA / Big Number ========================

rule RSA_PublicExponent {
    meta:
        description = "Common RSA Public Exponents"
        author = "CryptoDetect"
        algorithm = "RSA"
        confidence = 75
    strings:
        // e = 65537 (0x10001) in different endianness
        $e_65537_le = { 01 00 01 00 }
        $e_65537_be = { 00 01 00 01 }
        
        // e = 3
        $e_3 = { 03 00 00 00 }
    condition:
        any of them
}

// ======================== Elliptic Curve ========================

rule ECC_NIST_P256 {
    meta:
        description = "NIST P-256 Curve Parameters"
        author = "CryptoDetect"
        algorithm = "ECC-P256"
        confidence = 90
    strings:
        // P-256 prime field (first 16 bytes)
        $p256_p = { FF FF FF FF 00 00 00 01 00 00 00 00 00 00 00 00 }
        
        // P-256 order n (first 16 bytes)
        $p256_n = { FF FF FF FF 00 00 00 00 FF FF FF FF FF FF FF FF }
    condition:
        any of them
}

// ======================== HMAC / PBKDF2 ========================

rule HMAC_IPAD_OPAD {
    meta:
        description = "HMAC Inner/Outer Padding Constants"
        author = "CryptoDetect"
        algorithm = "HMAC"
        confidence = 70
    strings:
        // IPAD (0x36 repeated)
        $ipad = { 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 }
        
        // OPAD (0x5C repeated)
        $opad = { 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C 5C }
    condition:
        any of them
}

// ======================== CRC / Checksums ========================

rule CRC32_Polynomial {
    meta:
        description = "CRC32 Polynomial Tables"
        author = "CryptoDetect"
        algorithm = "CRC32"
        confidence = 80
    strings:
        // CRC32 IEEE polynomial (0xEDB88320) and first table entry
        $poly_le = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 }
    condition:
        $poly_le
}

// ======================== Compression (False Positive Filter) ========================

rule ZLIB_Deflate {
    meta:
        description = "ZLIB/Deflate Constants (to filter false positives)"
        author = "CryptoDetect"
        algorithm = "COMPRESSION"
        confidence = 60
    strings:
        $zlib_header = { 78 9C }  // ZLIB default compression
        $zlib_header2 = { 78 01 }  // ZLIB no compression
        $zlib_header3 = { 78 DA }  // ZLIB best compression
    condition:
        any of them
}
