import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

// Algorithm confidence heatmap colors
const ALGORITHM_COLORS = {
  'AES-128': '#ef4444',    // red-500
  'AES-192': '#f97316',    // orange-500
  'AES-256': '#eab308',    // yellow-500
  'ECC': '#22c55e',        // green-500
  'PRNG': '#06b6d4',       // cyan-500
  'RSA-1024': '#8b5cf6',   // violet-500
  'RSA-4096': '#a855f7',   // purple-500
  'SHA-1': '#ec4899',      // pink-500
  'SHA-224': '#f59e0b',    // amber-500
  'SHA-256': '#84cc16',    // lime-500
  'XOR-CIPHER': '#f43f5e', // rose-500
};

interface ConfidenceScore {
  avg_probability: number;
  max_probability: number;
  functions_with_significant_probability: number;
}

interface ConfidenceHeatmapProps {
  confidenceScores: Record<string, ConfidenceScore>;
}

export const ConfidenceHeatmap: React.FC<ConfidenceHeatmapProps> = ({
  confidenceScores,
}) => {
  const heatmapData = Object.entries(confidenceScores).map(([algorithm, scores]) => ({
    algorithm,
    avgProbability: (scores.avg_probability * 100).toFixed(2),
    maxProbability: (scores.max_probability * 100).toFixed(2),
    significantFunctions: scores.functions_with_significant_probability,
    color: ALGORITHM_COLORS[algorithm as keyof typeof ALGORITHM_COLORS] || '#64748b',
    rawAvg: scores.avg_probability,
    rawMax: scores.max_probability,
  }));

  // Sort by average probability (highest first)
  const sortedData = heatmapData.sort((a, b) => b.rawAvg - a.rawAvg);

  // Filter for significant algorithms (avg probability > 1%)
  const significantAlgorithms = sortedData.filter(item => item.rawAvg > 0.01);
  const minorAlgorithms = sortedData.filter(item => item.rawAvg <= 0.01);

  return (
    <div className="space-y-6">
      {/* Main Confidence Chart */}
      <Card>
        <CardHeader>
          <CardTitle>Algorithm Confidence Scores</CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={significantAlgorithms.slice(0, 8)} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="algorithm" 
                angle={-45} 
                textAnchor="end" 
                height={80}
                fontSize={12}
              />
              <YAxis 
                label={{ value: 'Confidence %', angle: -90, position: 'insideLeft' }}
                domain={[0, 100]}
              />
              <Tooltip 
                formatter={(value: number, name: string) => [
                  `${value}%`,
                  name === 'avgProbability' ? 'Avg Confidence' : 'Max Confidence'
                ]}
                labelFormatter={(label: string) => `Algorithm: ${label}`}
              />
              <Legend />
              <Bar 
                dataKey="avgProbability" 
                name="Average Confidence"
                fill="#3b82f6"
                radius={[2, 2, 0, 0]}
              />
              <Bar 
                dataKey="maxProbability" 
                name="Max Confidence"
                fill="#ef4444"
                radius={[2, 2, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Heatmap Grid */}
      <Card>
        <CardHeader>
          <CardTitle>Confidence Heatmap</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {sortedData.map((item) => {
              const intensity = Math.min(item.rawAvg * 10, 1); // Scale for visual intensity
              const opacityClass = intensity > 0.5 ? 'bg-opacity-80' : 'bg-opacity-40';
              
              return (
                <div
                  key={item.algorithm}
                  className={`p-3 rounded-lg border transition-all hover:scale-105 ${opacityClass}`}
                  style={{
                    backgroundColor: `${item.color}20`,
                    borderColor: item.color,
                  }}
                >
                  <div className="text-xs font-medium mb-1 truncate" title={item.algorithm}>
                    {item.algorithm}
                  </div>
                  <div className="text-lg font-bold" style={{ color: item.color }}>
                    {item.avgProbability}%
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Max: {item.maxProbability}%
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Functions: {item.significantFunctions}
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Algorithm Distribution Pie Chart */}
      {significantAlgorithms.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Top Algorithms Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={significantAlgorithms.slice(0, 6)}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ algorithm, avgProbability }) => `${algorithm}: ${avgProbability}%`}
                  outerRadius={100}
                  fill="#8884d8"
                  dataKey="rawAvg"
                >
                  {significantAlgorithms.slice(0, 6).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  formatter={(value: number) => [`${(value * 100).toFixed(2)}%`, 'Confidence']}
                />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}

      {/* Minor Algorithms Summary */}
      {minorAlgorithms.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Low Confidence Algorithms</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {minorAlgorithms.map((item) => (
                <Badge key={item.algorithm} variant="outline" className="text-xs">
                  {item.algorithm}: {item.avgProbability}%
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

interface AlgorithmDetectionChartProps {
  algorithmCounts: Record<string, number>;
  detectedAlgorithms: string[];
}

export const AlgorithmDetectionChart: React.FC<AlgorithmDetectionChartProps> = ({
  algorithmCounts,
  detectedAlgorithms,
}) => {
  const chartData = Object.entries(algorithmCounts)
    .map(([algorithm, count]) => ({
      algorithm,
      count,
      detected: detectedAlgorithms.includes(algorithm),
      color: ALGORITHM_COLORS[algorithm as keyof typeof ALGORITHM_COLORS] || '#64748b',
    }))
    .sort((a, b) => b.count - a.count);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Algorithm Detection Summary</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis 
              dataKey="algorithm" 
              angle={-45} 
              textAnchor="end" 
              height={80}
              fontSize={12}
            />
            <YAxis label={{ value: 'Detections', angle: -90, position: 'insideLeft' }} />
            <Tooltip 
              formatter={(value: number, name: string, props: any) => [
                `${value} detection${value !== 1 ? 's' : ''}`,
                props.payload.detected ? 'Detected Algorithm' : 'Algorithm'
              ]}
            />
            <Bar 
              dataKey="count" 
              name="Detections"
              radius={[4, 4, 0, 0]}
            >
              {chartData.map((entry, index) => (
                <Cell 
                  key={`cell-${index}`} 
                  fill={entry.detected ? entry.color : '#e5e7eb'} 
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        
        <div className="mt-4 flex flex-wrap gap-2">
          {detectedAlgorithms.map((algorithm) => (
            <Badge key={algorithm} className="bg-green-100 text-green-800 border-green-200">
              ✓ {algorithm}
            </Badge>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

interface FunctionPredictionsTableProps {
  functionPredictions: Array<{
    function_name: string;
    function_address: string;
    predicted_algorithm: string;
    confidence: number;
    is_crypto: boolean;
    top_3_predictions: Array<{
      rank: number;
      algorithm: string;
      probability: number;
      confidence_percent: number;
      algorithm_type: string;
    }>;
  }>;
}

export const FunctionPredictionsTable: React.FC<FunctionPredictionsTableProps> = ({
  functionPredictions,
}) => {
  const getConfidenceColor = (confidence: number) => {
    if (confidence > 0.8) return 'text-green-600 bg-green-50';
    if (confidence > 0.6) return 'text-yellow-600 bg-yellow-50';
    if (confidence > 0.4) return 'text-orange-600 bg-orange-50';
    return 'text-red-600 bg-red-50';
  };

  const getAlgorithmBadgeColor = (algorithm: string, isCrypto: boolean) => {
    if (!isCrypto) return 'bg-gray-100 text-gray-800 border-gray-200';
    
    const colors = {
      'AES-128': 'bg-red-100 text-red-800 border-red-200',
      'AES-192': 'bg-orange-100 text-orange-800 border-orange-200',
      'AES-256': 'bg-yellow-100 text-yellow-800 border-yellow-200',
      'XOR-CIPHER': 'bg-rose-100 text-rose-800 border-rose-200',
      'SHA-1': 'bg-pink-100 text-pink-800 border-pink-200',
      'SHA-256': 'bg-lime-100 text-lime-800 border-lime-200',
      'ECC': 'bg-green-100 text-green-800 border-green-200',
      'RSA-1024': 'bg-violet-100 text-violet-800 border-violet-200',
      'RSA-4096': 'bg-purple-100 text-purple-800 border-purple-200',
    };
    
    return colors[algorithm as keyof typeof colors] || 'bg-blue-100 text-blue-800 border-blue-200';
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Function Analysis Results</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {functionPredictions.map((func, index) => (
            <div key={index} className="border rounded-lg p-4 hover:bg-muted/50 transition-colors">
              <div className="flex flex-col md:flex-row md:items-center justify-between mb-3">
                <div>
                  <h4 className="font-mono font-semibold text-lg">{func.function_name}</h4>
                  <p className="text-sm text-muted-foreground">Address: {func.function_address}</p>
                </div>
                <div className="flex items-center gap-2 mt-2 md:mt-0">
                  <Badge 
                    variant="outline" 
                    className={getAlgorithmBadgeColor(func.predicted_algorithm, func.is_crypto)}
                  >
                    {func.predicted_algorithm}
                  </Badge>
                  <span className={`px-2 py-1 rounded text-sm font-medium ${getConfidenceColor(func.confidence)}`}>
                    {(func.confidence * 100).toFixed(1)}%
                  </span>
                </div>
              </div>

              {/* Top 3 Predictions */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                {func.top_3_predictions.map((pred) => (
                  <div key={pred.rank} className="p-2 bg-muted/30 rounded text-sm">
                    <div className="flex justify-between items-center">
                      <span className="font-medium">#{pred.rank} {pred.algorithm}</span>
                      <span className="text-xs text-muted-foreground">
                        {pred.confidence_percent.toFixed(1)}%
                      </span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {pred.algorithm_type}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default {
  ConfidenceHeatmap,
  AlgorithmDetectionChart,
  FunctionPredictionsTable,
};