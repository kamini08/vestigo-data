"""
LLM Crypto Analyzer Service
Sends crypto string detection results to Perplexity LLM for structured analysis
"""

import os
import json
from typing import Dict, Any, List, Optional
from openai import OpenAI
from config.logging_config import logger


class LLMCryptoAnalyzer:
    """Service for analyzing crypto strings using Perplexity LLM"""
    
    # Structured JSON schema that LLM must follow - based on user requirements
    RESPONSE_SCHEMA = {
        "crypto_algorithms": {
            "symmetric": [],  # e.g., ["AES-128-CBC", "AES-256-GCM", "CHACHA20", "chacha20-poly1305"]
            "hashes": [],  # e.g., ["SHA1", "SHA256", "SHA384", "SHA512", "SHA3-256", "md5WithRSAEncryption"]
            "mac_kdf": []  # e.g., ["HMAC", "PBKDF2", "HKDF"]
        },
        "public_key_algorithms": {
            "rsa": [],  # e.g., ["RSA", "RSA-PSS", "rsaEncryption", "RSA Public-Key"]
            "ecdsa_ecdh": []  # e.g., ["ECDH", "ECDSA", "Curve25519", "X25519", "ED25519", "SECP256R1"]
        },
        "tls_versions": [],  # e.g., ["TLSv1", "TLSv1.2", "TLSv1.3", "DTLSv1", "SSLv3"]
        "certificate_blocks": [],  # e.g., ["-----BEGIN CERTIFICATE-----", "-----BEGIN PRIVATE KEY-----"]
        "crypto_libraries": {
            "detected": [],  # e.g., ["wolfSSL", "OpenSSL", "mbedTLS"]
            "version": "",  # e.g., "wolfSSL 5.8.0"
            "source_files": [],  # e.g., ["./src/x509.c", "./src/x509_str.c"]
        },
        "tls_handshake_states": [],  # e.g., ["Server Hello", "Client Hello", "Certificate"]
        "network_protocols": {
            "http": [],  # e.g., ["HTTP/1.1", "HTTP/2", "GET /", "POST /"]
            "iot": [],  # e.g., ["MQTT", "CoAP", "websocket"]
            "industrial": []  # e.g., ["Modbus", "DNP3", "IEC104", "BACnet", "OPC UA"]
        },
        "authentication": {
            "methods": [],  # e.g., ["JWT", "OAuth", "OpenID"]
            "tokens": [],  # e.g., ["access_token", "refresh_token"]
            "algorithms": []  # e.g., ["HS256", "RS256", "ES256"]
        },
        "certificate_authorities": {
            "ca_paths": [],  # e.g., ["/etc/ssl", "/etc/pki"]
            "ca_files": [],  # e.g., ["CAfile", "CApath"]
            "certificate_types": []  # e.g., ["X509", "OCSP", "CRL"]
        },
        "security_features": {
            "key_exchange": [],  # e.g., ["ECDHE", "DHE"]
            "cipher_modes": [],  # e.g., ["GCM", "CCM", "CBC", "XTS"]
            "extensions": [],  # e.g., ["ALPN", "0-RTT", "KeyUpdate"]
            "session_management": []  # e.g., ["NewSessionTicket", "pre-shared key"]
        },
        "architecture_indicators": {
            "detected_arch": "",  # "ARM", "x86", "MIPS", "unknown"
            "confidence": "",  # "high", "medium", "low"
            "evidence": []  # Specific strings indicating architecture
        },
        "behavioral_analysis": {
            "crypto_usage": "",  # "Client", "Server", "Both", "Unknown"
            "likely_purpose": "",  # "IoT Device", "Router", "VPN", "Web Server", etc.
            "security_level": "",  # "High", "Medium", "Low"
            "concerns": []  # e.g., ["Weak algorithms detected", "Hardcoded keys"]
        },
        "verdict": {
            "summary": "",  # One-line verdict
            "confidence": "",  # "high", "medium", "low"
            "risk_level": "",  # "critical", "high", "medium", "low"
            "key_findings": []  # List of key findings
        }
    }
    
    ANALYSIS_PROMPT = """You are a firmware security analyst specializing in cryptographic implementations. 
Analyze the following strings extracted from a binary file and provide a structured JSON response.

**CRITICAL: Your response MUST be ONLY valid JSON matching the exact schema provided. No markdown, no explanations, just pure JSON.**

Binary Information:
- File Type: {file_type}
- Total Strings: {total_strings}
- Crypto-related Strings: {crypto_count}

Categorized Strings:
{categorized_strings}

All Crypto Strings (first 100):
{crypto_strings}

Your task:
0. VERY IMPORTANT: try to detect architecture the architecture_indicators must not be empty (among aarch64, mips, risv, arm)
1. Identify specific cryptographic primitives (algorithms, modes, hash functions)
2. Detect certificates, PKI infrastructure, and PKCS standards
3. Identify crypto libraries and versions
4. Analyze network protocols (TLS/SSL, HTTP, IoT protocols)
5. Assess behavioral indicators of crypto usage
6. Determine architecture and platform
7. Provide a security assessment with one-liner verdict
8. Note session management mechanisms 

Response Schema (YOU MUST FOLLOW THIS EXACTLY):
{schema}

Guidelines:
- Be specific: "AES-256-GCM" not just "AES"
- Include version numbers when detected: "TLSv1.3" not just "TLS"
- Extract actual library names and versions: "OpenSSL 1.1.1k"
- Provide confidence levels based on evidence strength
- The verdict should be a clear, concise one-liner (max 100 chars)
- List actual findings, not possibilities. In case you don't find any actual, you can add possibilities but it should look accurate
- If not detected, use empty arrays [] or false, not null
- For unknown fields, use "unknown" string

Return ONLY the JSON object, nothing else."""

    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize LLM analyzer with Perplexity client"""
        self.api_key = api_key or os.environ.get("PERPLEXITY_API_KEY")
        
        if not self.api_key:
            logger.warning("Perplexity API key not found. LLM analysis will be disabled.")
            self.client = None
        else:
            # Initialize OpenAI client with Perplexity endpoint
            self.client = OpenAI(
                api_key=self.api_key,
                base_url="https://api.perplexity.ai"
            )
            logger.info("LLM Crypto Analyzer initialized with Perplexity")
    
    def analyze_crypto_strings(
        self, 
        crypto_strings: List[str],
        binary_name: str,
        file_type: str = "unknown",
        job_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze crypto strings using LLM to extract structured information
        
        Args:
            crypto_strings: List of crypto-related strings
            binary_name: Name of the binary file
            file_type: Type of file being analyzed
            job_id: Optional job ID for logging
            
        Returns:
            Structured analysis results matching RESPONSE_SCHEMA
        """
        log_prefix = f"JobID: {job_id} - " if job_id else ""
        
        if not self.client:
            logger.warning(f"{log_prefix}LLM analysis skipped - Perplexity client not initialized")
            return {"status": "skipped", "reason": "Perplexity API key not configured"}
        
        if not crypto_strings:
            logger.info(f"{log_prefix}No crypto strings to analyze")
            return {"status": "no_data", "reason": "No crypto strings found"}
        
        try:
            logger.info(f"{log_prefix}Starting analysis of {len(crypto_strings)} crypto strings")
            
            # Prepare prompt with data
            prompt = self._prepare_prompt(crypto_strings, binary_name, file_type)
            
            # Call Perplexity API (using OpenAI SDK format)
            response = self.client.chat.completions.create(
                model="sonar",  # Perplexity's sonar model
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in cryptography and firmware analysis. You MUST respond with ONLY valid JSON. No explanations, no markdown, no extra text - just pure valid JSON that can be parsed by json.loads()."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,  # Low temperature for consistent structured output
                max_tokens=4000,  # Increased for complete responses
                response_format={"type": "json_object"} if "sonar" not in "sonar" else None  # Request JSON mode if supported
            )
            
            # Parse response
            result_text = response.choices[0].message.content.strip()
            
            # Remove markdown code blocks if present
            if result_text.startswith("```"):
                lines = result_text.split("\n")
                # Remove first line with ```json or ```
                lines = lines[1:]
                # Remove last line with ```
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                result_text = "\n".join(lines).strip()
            
            # Try to extract JSON if there's extra text
            if not result_text.startswith("{"):
                # Look for first { and last }
                start_idx = result_text.find("{")
                end_idx = result_text.rfind("}")
                if start_idx != -1 and end_idx != -1:
                    result_text = result_text[start_idx:end_idx+1]
            
            # Clean up common JSON errors
            result_text = result_text.replace("\n", " ")  # Remove newlines that might break strings
            result_text = result_text.replace("\\", "\\\\")  # Escape backslashes
            
            try:
                result = json.loads(result_text)
            except json.JSONDecodeError:
                # If still failing, log the problematic response and return error with partial data
                logger.error(f"{log_prefix}Raw LLM response that failed to parse: {result_text[:500]}...")
                return {
                    "status": "error",
                    "error": "LLM returned malformed JSON",
                    "raw_response_preview": result_text[:200]
                }
            
            # Add metadata
            result["status"] = "success"
            result["llm_model"] = "sonar"
            result["tokens_used"] = response.usage.total_tokens if hasattr(response.usage, 'total_tokens') else 0
            
            logger.info(f"{log_prefix}LLM analysis complete - Tokens: {result['tokens_used']}")
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"{log_prefix}Failed to parse LLM JSON response: {str(e)}")
            return {"status": "error", "error": f"JSON parsing failed: {str(e)}"}
        except Exception as e:
            logger.error(f"{log_prefix}LLM analysis error: {str(e)}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    def _prepare_prompt(self, crypto_strings: List[str], binary_name: str, file_type: str) -> str:
        """Prepare the analysis prompt with data"""
        
        # Limit strings to avoid token limits (keep first 300 for better coverage)
        strings_sample = crypto_strings[:300]
        strings_text = "\n".join([f"- {s}" for s in strings_sample])
        
        schema_json = json.dumps(self.RESPONSE_SCHEMA, indent=2)
        
        prompt = f"""CRITICAL: Respond with ONLY valid JSON. Start with {{ and end with }}.

Analyze these cryptographic strings from binary: {binary_name}

STRINGS TO ANALYZE ({len(strings_sample)} of {len(crypto_strings)} total):
{strings_text}

EXTRACTION GUIDELINES:
1. CRYPTO ALGORITHMS: Look for algorithm names (AES, RSA, SHA, CHACHA20, etc.) with modes/sizes
   - Symmetric: AES-128-CBC, AES-256-GCM, CHACHA20-POLY1305, aes128, aes256
   - Hashes: SHA256, SHA512, SHA1, MD5, SHA3-256
   - MAC/KDF: HMAC, PBKDF2, HKDF

2. PUBLIC KEY: Extract RSA/ECC algorithms
   - RSA: "RSA", "rsaEncryption", "RSA Public-Key", "RSA-PSS"
   - ECDSA/ECDH: "ECDH", "ECDHE", "ECDSA", "Curve25519", "X25519", "SECP256R1"

3. TLS VERSIONS: Look for TLS/SSL/DTLS version strings
   - Examples: "TLSv1.2", "TLSv1.3", "DTLSv1", "SSLv3"

4. TLS HANDSHAKE STATES: **ONLY include if these exact strings are present in the crypto strings above**
  - **If none of these handshake strings are found, leave tls_handshake_states as empty array []**

5. CRYPTO LIBRARIES: Identify library names and versions
   - Look for: "wolfSSL", "OpenSSL", "mbedTLS", "BoringSSL"
   - Version patterns: "wolfSSL 5.8.0", "OpenSSL 1.1.1"
   - Source files: "./src/x509.c", "ssl.c"
   - Error messages: "RSA_new failed", "InitRsaKey failure"

6. CERTIFICATE BLOCKS: PEM format markers
   - "-----BEGIN CERTIFICATE-----", "-----BEGIN PRIVATE KEY-----", etc.

7. NETWORK PROTOCOLS: HTTP, IoT, Industrial protocols
   - HTTP: "HTTP/1.1", "HTTP/2", "GET /", "POST /"
   - IoT: "MQTT", "CoAP", "websocket"
   - Industrial: "Modbus", "DNP3", "OPC UA"

8. ARCHITECTURE INDICATORS: Look for architecture-specific strings
   - ARM: "armv7", "aarch64", "ARM", "thumb"
   - x86: "x86_64", "i386", "amd64"
   - MIPS: "mips", "mipsel"
   - Evidence: Register names, calling conventions, library paths

9. SECURITY FEATURES:
   - Key exchange: "ECDHE", "DHE", "RSA key exchange"
   - Cipher modes: "GCM", "CBC", "CCM", "CTR"
   - Extensions: "ALPN", "SNI", "0-RTT"

10. BEHAVIORAL ANALYSIS: Determine usage pattern
    - Check for "Server" vs "Client" strings
    - Infer purpose from protocols (IoT, Router, VPN, Web Server)
    - Assess security level from algorithm strength

RESPONSE SCHEMA:
{schema_json}

CRITICAL RULES:
- Include items ONLY if found in strings above
- Empty categories: use [] for arrays, "" for strings
- Don't invent data - extract only what's visible
- For architecture: check for arch-specific strings (armv7, x86_64, mips, etc.)
- For TLS handshake: **ONLY include if actual handshake strings like "Hello", "Certificate", "Finished", "Key Exchange" are found in the strings above. If not found, tls_handshake_states must be []**
- verdict.summary: ONE sentence, max 100 chars

Return ONLY the JSON object now:"""

        return prompt


# Singleton instance
llm_crypto_analyzer = LLMCryptoAnalyzer()
