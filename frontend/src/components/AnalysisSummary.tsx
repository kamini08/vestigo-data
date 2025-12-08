import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  Brain, 
  Activity, 
  Cpu,
  FileText,
  AlertCircle,
  CheckCircle,
  Clock,
  TrendingUp,
} from 'lucide-react';

interface AnalysisSummaryProps {
  jobData: unknown;
}

export const AnalysisSummary: React.FC<AnalysisSummaryProps> = ({ jobData }) => {
  const extractAnalysisMetrics = () => {
    if (!jobData || typeof jobData !== 'object') {
      return {
        hasFeatureExtraction: false,
        hasMLClassification: false,
        hasQilingAnalysis: false,
        totalFunctions: 0,
        cryptoFunctions: 0,
        confidenceScore: 0,
        detectedAlgorithms: [],
        analysisStatus: 'unknown',
      };
    }

    const data = jobData as Record<string, unknown>;
    const featureResults = data.feature_extraction_results as Record<string, unknown>;
    const mlClassification = featureResults?.ml_classification as Record<string, unknown>;
    const qilingResults = data.qiling_dynamic_results as Record<string, unknown>;

    return {
      hasFeatureExtraction: !!featureResults,
      hasMLClassification: !!mlClassification,
      hasQilingAnalysis: !!qilingResults,
      totalFunctions: (featureResults?.summary as Record<string, unknown>)?.total_functions as number || 0,
      cryptoFunctions: (featureResults?.summary as Record<string, unknown>)?.crypto_functions as number || 0,
      confidenceScore: (mlClassification?.file_summary as Record<string, unknown>)?.average_confidence as number || 0,
      detectedAlgorithms: (mlClassification?.file_summary as Record<string, unknown>)?.detected_algorithms as string[] || [],
      analysisStatus: data.status as string || 'unknown',
      cryptoPercentage: (mlClassification?.file_summary as Record<string, unknown>)?.crypto_percentage as number || 0,
      fileStatus: (mlClassification?.file_summary as Record<string, unknown>)?.file_status as string || 'unknown',
    };
  };

  const metrics = extractAnalysisMetrics();

  const getAnalysisCompleteness = () => {
    let completed = 0;
    const total = 3; // Feature extraction, ML classification, Qiling

    if (metrics.hasFeatureExtraction) completed++;
    if (metrics.hasMLClassification) completed++;
    if (metrics.hasQilingAnalysis) completed++;

    return (completed / total) * 100;
  };

  const getOverallRiskLevel = () => {
    if (metrics.cryptoPercentage >= 80) return { level: 'High', color: 'text-red-600 bg-red-50 border-red-200' };
    if (metrics.cryptoPercentage >= 50) return { level: 'Medium', color: 'text-orange-600 bg-orange-50 border-orange-200' };
    if (metrics.cryptoPercentage >= 20) return { level: 'Low', color: 'text-yellow-600 bg-yellow-50 border-yellow-200' };
    return { level: 'Minimal', color: 'text-green-600 bg-green-50 border-green-200' };
  };

  const completeness = getAnalysisCompleteness();
  const riskLevel = getOverallRiskLevel();

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* Analysis Completeness */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center">
            <Clock className="h-8 w-8 text-blue-600" />
            <div className="ml-4 flex-1">
              <p className="text-sm font-medium text-muted-foreground">Analysis Progress</p>
              <div className="text-2xl font-bold">{completeness.toFixed(0)}%</div>
              <Progress value={completeness} className="mt-2 h-2" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Risk Assessment */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center">
            <Shield className="h-8 w-8 text-orange-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Risk Level</p>
              <Badge className={riskLevel.color}>
                {riskLevel.level}
              </Badge>
              <p className="text-xs text-muted-foreground mt-1">
                {metrics.cryptoPercentage}% crypto content
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Function Analysis */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center">
            <Activity className="h-8 w-8 text-green-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Functions Analyzed</p>
              <div className="text-2xl font-bold">{metrics.totalFunctions}</div>
              <p className="text-xs text-muted-foreground">
                {metrics.cryptoFunctions} crypto functions
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ML Confidence */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center">
            <Brain className="h-8 w-8 text-purple-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">ML Confidence</p>
              <div className="text-2xl font-bold">
                {metrics.hasMLClassification ? `${(metrics.confidenceScore * 100).toFixed(1)}%` : 'N/A'}
              </div>
              <p className="text-xs text-muted-foreground">
                {metrics.detectedAlgorithms.length} algorithms detected
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

interface AnalysisStatusIndicatorProps {
  status: string;
  hasFeatureExtraction: boolean;
  hasMLClassification: boolean;
  hasQilingAnalysis: boolean;
}

export const AnalysisStatusIndicator: React.FC<AnalysisStatusIndicatorProps> = ({
  status,
  hasFeatureExtraction,
  hasMLClassification,
  hasQilingAnalysis,
}) => {
  const getStatusIcon = (completed: boolean) => {
    return completed ? (
      <CheckCircle className="w-5 h-5 text-green-600" />
    ) : (
      <AlertCircle className="w-5 h-5 text-yellow-600" />
    );
  };

  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <TrendingUp className="w-5 h-5" />
          Analysis Pipeline Status
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
            <div className="flex items-center gap-3">
              {getStatusIcon(hasFeatureExtraction)}
              <span className="font-medium">Feature Extraction</span>
            </div>
            <Badge variant={hasFeatureExtraction ? "default" : "secondary"}>
              {hasFeatureExtraction ? "Complete" : "Pending"}
            </Badge>
          </div>

          <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
            <div className="flex items-center gap-3">
              {getStatusIcon(hasMLClassification)}
              <span className="font-medium">ML Classification</span>
            </div>
            <Badge variant={hasMLClassification ? "default" : "secondary"}>
              {hasMLClassification ? "Complete" : "Pending"}
            </Badge>
          </div>

          <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
            <div className="flex items-center gap-3">
              {getStatusIcon(hasQilingAnalysis)}
              <span className="font-medium">Dynamic Analysis</span>
            </div>
            <Badge variant={hasQilingAnalysis ? "default" : "secondary"}>
              {hasQilingAnalysis ? "Complete" : "Pending"}
            </Badge>
          </div>
        </div>

        <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-blue-600" />
            <span className="text-sm font-medium text-blue-800">Overall Status:</span>
            <Badge className="bg-blue-100 text-blue-800 border-blue-200">
              {status?.toUpperCase() || 'PROCESSING'}
            </Badge>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};