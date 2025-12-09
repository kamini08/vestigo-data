"""
LLM Analysis Service for Vestigo Backend
Integrates OpenAI GPT-4 to analyze strace logs for crypto detection
Based on qiling_analysis/tests/llm/engine.py
"""

import os
import json
import time
from typing import Dict, Any, Optional
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from openai import OpenAI
from config.logging_config import logger


class LLMAnalysisService:
    """
    Service for LLM-powered analysis of strace logs to detect cryptographic implementations.
    
    This service:
    1. Takes strace logs and qiling analysis results
    2. Sends them to OpenAI GPT for intelligent crypto detection
    3. Returns structured analysis with algorithm identification and confidence scores
    """
    
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            logger.warning("OPENAI_API_KEY not found in environment - LLM analysis disabled")
            self.enabled = False
        else:
            self.client = OpenAI(api_key=self.api_key)
            self.enabled = True
            logger.info("LLMAnalysisService initialized with OpenAI API")
        
        # Model configuration
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o")
        self.max_tokens = 4096
        self.temperature = 0
        
        logger.info(f"LLM Model: {self.model}")
    
    async def analyze_crypto_telemetry(
        self, 
        job_id: str, 
        strace_log_path: str,
        qiling_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze strace logs using LLM to detect and classify cryptographic implementations.
        
        Args:
            job_id: Unique identifier for this analysis job
            strace_log_path: Path to the strace log file
            qiling_results: Optional qiling dynamic analysis results for context
            
        Returns:
            Dict containing LLM analysis results with crypto classification
        """
        if not self.enabled:
            logger.warning(f"LLM analysis disabled (no API key) - JobID: {job_id}")
            return self._create_disabled_result(job_id)
        
        logger.info(f"Starting LLM analysis - JobID: {job_id}, Strace: {strace_log_path}")
        
        try:
            # Load strace log
            if not os.path.exists(strace_log_path):
                logger.error(f"Strace log not found: {strace_log_path}")
                return self._create_error_result(job_id, "Strace log file not found")
            
            strace_content = self._load_text(strace_log_path)
            
            # Find and load analysis log (raw analysis output)
            analysis_log_content = None
            analysis_log_path = None
            try:
                # Convert strace log path to analysis log path
                # strace_logs/strace_binary_TIMESTAMP.log -> analysis_logs/analysis_binary_TIMESTAMP.log
                strace_path_obj = Path(strace_log_path)
                analysis_log_dir = strace_path_obj.parent.parent / "analysis_logs"
                
                # Get the binary identifier from strace log name
                strace_name = strace_path_obj.stem  # e.g., strace_binary_TIMESTAMP
                if strace_name.startswith("strace_"):
                    binary_identifier = strace_name[7:]  # Remove "strace_" prefix
                    analysis_pattern = f"analysis_{binary_identifier}*.log"
                    
                    # Find matching analysis logs
                    matching_logs = list(analysis_log_dir.glob(analysis_pattern))
                    if matching_logs:
                        # Use the most recent analysis log
                        analysis_log_path_obj = sorted(matching_logs)[-1]
                        analysis_log_path = str(analysis_log_path_obj)
                        analysis_log_content = self._load_text(analysis_log_path)
                        logger.info(f"Found analysis log: {analysis_log_path}")
                    else:
                        logger.warning(f"No analysis log found with pattern: {analysis_pattern}")
            except Exception as e:
                logger.warning(f"Could not load analysis log: {str(e)}")
            
            # Build prompt and call LLM (only sends strace to LLM as per engine.py)
            prompt = self._build_strace_prompt(strace_content, qiling_results)
            llm_response = await self._call_llm(prompt)
            
            # Structure the result matching engine.py output format
            import datetime
            result = {
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                "analysis_file": analysis_log_path if analysis_log_path else "not_found",
                "strace_file": strace_log_path,
                
                # RAW analysis section (preserved as text, not processed by LLM)
                "analysis_section": analysis_log_content if analysis_log_content else "Analysis log not available",
                
                # LLM-evaluated STRACE section
                "strace_section": llm_response,
                
                # Legacy fields for backward compatibility
                "job_id": job_id,
                "analysis_timestamp": time.time(),
                "analysis_tool": "llm_crypto_classifier",
                "model": self.model,
                "strace_log_path": strace_log_path,
                "status": "completed",
                "llm_classification": llm_response,
                "qiling_context": {
                    "crypto_detected": qiling_results.get("verdict", {}).get("crypto_detected", False) if qiling_results else None,
                    "detected_algorithms": qiling_results.get("phases", {}).get("constant_detection", {}).get("algorithms_detected", []) if qiling_results else []
                }
            }
            
            logger.info(f"LLM analysis completed - JobID: {job_id}, "
                       f"Classification: {llm_response.get('crypto_classification', 'UNKNOWN')}, "
                       f"Algorithm: {llm_response.get('crypto_algorithm', 'unknown')}, "
                       f"Confidence: {llm_response.get('confidence', 0.0)}")
            
            return result
            
        except Exception as e:
            logger.error(f"LLM analysis failed - JobID: {job_id}: {str(e)}", exc_info=True)
            return self._create_error_result(job_id, str(e))
    
    def _load_text(self, path: str) -> str:
        """Load text file with error handling"""
        try:
            file_path = Path(path)
            return file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.error(f"Error reading file {path}: {str(e)}")
            raise
    
    def _build_strace_prompt(self, strace_log: str, qiling_results: Optional[Dict[str, Any]] = None) -> str:
        """
        Build the LLM prompt for strace analysis.
        Optionally includes qiling context for better accuracy.
        """
        
        # Base prompt for strace analysis
        base_prompt = f"""
You are a world-class firmware cryptography analyst.

You are given a Linux STRACE syscall log for a single execution of a binary.

Your job is to THINK CAREFULLY and decide, based ONLY on what STRACE can reveal:

1. Does this execution involve any cryptographic behavior at all?
   - Look for:
     - getrandom()/urandom usage
     - read/write of suspicious binary buffers
     - "Original" vs "Encrypted" style prints
     - repeated patterns suggesting encryption, hashing, or key generation
   - If there is clearly no crypto-like activity, classify as NON_CRYPTO.

2. If there IS crypto-like behavior, decide whether it is:
   - STANDARD_CRYPTO:
     One of the following algorithms:
     [
       "AES", "ARIA", "CMAC", "Camellia", "ChaCha20",
       "DES", "DH", "DSA", "ECC", "HMAC", "MD5",
       "RSA", "SEED", "SHA-1", "SHA-224", "SHA-256",
       "SHA-3", "SHA-512"
     ]
   - PROPRIETARY_CRYPTO:
     A custom / home-grown / non-standard cipher, stream, hash, or MAC.

   You MUST NOT blindly default to AES or any other algorithm.
   - Only choose "AES" if the behavior strongly matches AES usage patterns.
   - Only choose another STANDARD algorithm if there is a solid, defensible reason.
   - If the behavior is clearly crypto but does NOT convincingly match any standard algorithm,
     THEN (and only then) classify as PROPRIETARY_CRYPTO.

3. For PROPRIETARY_CRYPTO:
   - Provide a detailed technical analysis grounded in FACTS visible in STRACE
   - For the field "crypto_algorithm", provide a short descriptive label like:
     - "proprietary_stream_cipher"
     - "proprietary_xor_rotate_cipher"
     - "proprietary_block_cipher"
     - "proprietary_hash_like_function"

4. For STANDARD_CRYPTO:
   - Set "crypto_algorithm" to the exact name from the allowed list
   - Give short reasoning based on STRACE evidence

5. For NON_CRYPTO:
   - Set "crypto_classification" to "NON_CRYPTO"
   - Set "crypto_algorithm" to "none"
   - Explain why the behavior appears non-cryptographic

Your mandatory JSON output format (no extra keys, no extra text):

{{
  "crypto_classification": "STANDARD_CRYPTO" | "PROPRIETARY_CRYPTO" | "NON_CRYPTO",
  "crypto_algorithm": "",
  "is_proprietary": false,
  "reasoning": "",
  "confidence": 0.0,
  "proprietary_analysis": {{
    "summary": "",
    "evidence": [
      {{
        "fact": "",
        "support": ""
      }}
    ]
  }}
}}"""

        # Add qiling context if available
        if qiling_results:
            qiling_context = f"""

ADDITIONAL CONTEXT FROM STATIC ANALYSIS:
- Qiling detected crypto: {qiling_results.get('verdict', {}).get('crypto_detected', False)}
- YARA detected: {', '.join(qiling_results.get('phases', {}).get('yara_analysis', {}).get('detected', []))}
- Constants detected: {', '.join(qiling_results.get('phases', {}).get('constant_detection', {}).get('algorithms_detected', []))}

Use this context to VALIDATE your strace analysis, but do NOT blindly trust it.
The strace log is the PRIMARY source of truth.
"""
            base_prompt += qiling_context
        
        base_prompt += f"""

────────────────────────────────────────
STRACE LOG:
────────────────────────────────────────
{strace_log}
"""
        
        return base_prompt
    
    async def _call_llm(self, prompt: str) -> Dict[str, Any]:
        """Call OpenAI API with the constructed prompt"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You must return ONLY valid JSON that strictly follows the requested schema."
                    },
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            
            return json.loads(response.choices[0].message.content)
            
        except Exception as e:
            logger.error(f"OpenAI API call failed: {str(e)}")
            raise
    
    def _create_disabled_result(self, job_id: str) -> Dict[str, Any]:
        """Create result for when LLM is disabled"""
        return {
            "job_id": job_id,
            "analysis_timestamp": time.time(),
            "analysis_tool": "llm_crypto_classifier",
            "status": "disabled",
            "error": "LLM analysis disabled - OPENAI_API_KEY not configured",
            "llm_classification": None
        }
    
    def _create_error_result(self, job_id: str, error_message: str) -> Dict[str, Any]:
        """Create result for analysis errors"""
        return {
            "job_id": job_id,
            "analysis_timestamp": time.time(),
            "analysis_tool": "llm_crypto_classifier",
            "status": "failed",
            "error": error_message,
            "llm_classification": None
        }
