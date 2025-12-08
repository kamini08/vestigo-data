import React from 'react';
import { AnalysisSummary, AnalysisStatusIndicator } from './AnalysisSummary';
import { ConfidenceHeatmap, AlgorithmDetectionChart, FunctionPredictionsTable } from './AnalysisCharts';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';

// Sample data based on the JSON structure you provided
const sampleAnalysisData = {
  "job_id": "74669861-a538-4fe8-9710-423f47137f3d",
  "filename": "wolfssl_chacha_arm32_O1.o",
  "file_size": 28912,
  "status": "features_complete",
  "routing_decision": "PATH_A_BARE_METAL",
  "file_type": "ELF 32-bit LSB relocatable, ARM, EABI5 version 1 (SYSV), with debug_info, not stripped",
  "feature_extraction_results": {
    "job_id": "74669861-a538-4fe8-9710-423f47137f3d",
    "summary": {
      "total_functions": 5,
      "crypto_functions": 4,
      "non_crypto_functions": 0,
      "average_entropy": 2.2231,
      "binary_sections": {
        "text_size": 1520,
        "rodata_size": 32,
        "data_size": 0
      }
    },
    "ml_classification": {
      "status": "completed",
      "function_predictions": [
        {
          "function_name": "wc_Chacha_wordtobyte",
          "function_address": "00010000",
          "predicted_algorithm": "AES-128",
          "confidence": 0.4960060899352178,
          "is_crypto": true,
          "top_3_predictions": [
            {
              "rank": 1,
              "algorithm": "AES-128",
              "probability": 0.4960060899352178,
              "confidence_percent": 49.600608993521774,
              "algorithm_type": "symmetric-encryption"
            },
            {
              "rank": 2,
              "algorithm": "XOR-CIPHER",
              "probability": 0.4857255870267762,
              "confidence_percent": 48.57255870267762,
              "algorithm_type": "cryptographic"
            },
            {
              "rank": 3,
              "algorithm": "SHA-1",
              "probability": 0.01312994969592314,
              "confidence_percent": 1.312994969592314,
              "algorithm_type": "hash-function"
            }
          ]
        },
        {
          "function_name": "wc_Chacha_Process",
          "function_address": "000103f4",
          "predicted_algorithm": "XOR-CIPHER",
          "confidence": 0.9120935908064959,
          "is_crypto": true,
          "top_3_predictions": [
            {
              "rank": 1,
              "algorithm": "XOR-CIPHER",
              "probability": 0.9120935908064959,
              "confidence_percent": 91.20935908064959,
              "algorithm_type": "cryptographic"
            },
            {
              "rank": 2,
              "algorithm": "AES-128",
              "probability": 0.06179601575287824,
              "confidence_percent": 6.179601575287824,
              "algorithm_type": "symmetric-encryption"
            },
            {
              "rank": 3,
              "algorithm": "SHA-1",
              "probability": 0.014327142734337316,
              "confidence_percent": 1.4327142734337317,
              "algorithm_type": "hash-function"
            }
          ]
        }
      ],
      "file_summary": {
        "file_status": "CRYPTO_HEAVY",
        "crypto_percentage": 80.0,
        "average_confidence": 0.6832700114339949,
        "detected_algorithms": ["AES-128", "XOR-CIPHER"],
        "algorithm_counts": {
          "AES-128": 2,
          "Non-Crypto": 1,
          "XOR-CIPHER": 2
        },
        "confidence_scores": {
          "AES-128": {
            "avg_probability": 0.2671016818687493,
            "max_probability": 0.6049834234280365,
            "functions_with_significant_probability": 5
          },
          "XOR-CIPHER": {
            "avg_probability": 0.39323381227593995,
            "max_probability": 0.9120935908064959,
            "functions_with_significant_probability": 4
          },
          "SHA-1": {
            "avg_probability": 0.14811494674149236,
            "max_probability": 0.4082049593406803,
            "functions_with_significant_probability": 4
          },
          "ECC": {
            "avg_probability": 0.004933549509475302,
            "max_probability": 0.009970321153596647,
            "functions_with_significant_probability": 0
          },
          "RSA-1024": {
            "avg_probability": 0.00041844352458044804,
            "max_probability": 0.0014660154431697387,
            "functions_with_significant_probability": 0
          }
        }
      }
    }
  },
  "qiling_dynamic_results": {
    "status": "failed",
    "execution_time": 1.2555453777313232,
    "phases": {
      "yara_analysis": {
        "detected": ["COMPRESSION", "ChaCha20", "RSA", "Salsa20"],
        "total_matches": 23
      },
      "constant_detection": {
        "algorithms_detected": ["ChaCha20"],
        "count": 1
      },
      "function_symbols": {
        "detected": false,
        "stripped": true
      }
    },
    "verdict": {
      "crypto_detected": false,
      "confidence": "UNKNOWN",
      "confidence_score": 0
    }
  }
};

export const AnalysisDemo: React.FC = () => {
  const mlData = sampleAnalysisData.feature_extraction_results.ml_classification;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="text-center mb-8">
        <h1 className="text-4xl font-bold mb-2">Vestigo Analysis Dashboard Demo</h1>
        <p className="text-muted-foreground">
          Interactive visualization of binary analysis results
        </p>
      </div>

      {/* Analysis Summary */}
      <AnalysisSummary jobData={sampleAnalysisData} />

      {/* Status Indicator */}
      <AnalysisStatusIndicator 
        status={sampleAnalysisData.status}
        hasFeatureExtraction={true}
        hasMLClassification={true}
        hasQilingAnalysis={true}
      />

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <ConfidenceHeatmap confidenceScores={mlData.file_summary.confidence_scores} />
        </div>
        <div>
          <AlgorithmDetectionChart 
            algorithmCounts={mlData.file_summary.algorithm_counts}
            detectedAlgorithms={mlData.file_summary.detected_algorithms}
          />
        </div>
      </div>

      {/* Function Analysis */}
      <FunctionPredictionsTable functionPredictions={mlData.function_predictions} />

      {/* Sample File Info */}
      <Card>
        <CardHeader>
          <CardTitle>Sample Analysis Data</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-3 bg-muted rounded-lg">
              <div className="text-lg font-bold">ChaCha20</div>
              <div className="text-sm text-muted-foreground">Primary Algorithm</div>
            </div>
            <div className="text-center p-3 bg-muted rounded-lg">
              <div className="text-lg font-bold">80%</div>
              <div className="text-sm text-muted-foreground">Crypto Content</div>
            </div>
            <div className="text-center p-3 bg-muted rounded-lg">
              <div className="text-lg font-bold">5</div>
              <div className="text-sm text-muted-foreground">Functions</div>
            </div>
            <div className="text-center p-3 bg-muted rounded-lg">
              <div className="text-lg font-bold">68.3%</div>
              <div className="text-sm text-muted-foreground">Avg Confidence</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};