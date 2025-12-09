import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Navbar } from "@/components/Navbar";
import { Footer } from "@/components/Footer";
import { ArrowLeft, Download, ZoomIn, ZoomOut, Maximize2, Code2, Network, AlertTriangle } from "lucide-react";
import { API_CONFIG } from "@/config/api";

interface CFGData {
  jobId: string;
  status: string;
  analysis_output: string;
  architecture: string;
  cfg_directory: string;
  latest_cfg_png: string;
  generated_files: {
    control_flow_txt: string[];
    cfg_dot: string[];
    cfg_png: string[];
  };
  exit_code: number;
}

const CFGView = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const [cfgData, setCfgData] = useState<CFGData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [imageUrl, setImageUrl] = useState<string>("");
  const [zoom, setZoom] = useState(1);
  const imageContainerRef = useRef<HTMLDivElement>(null);
  const imageRef = useRef<HTMLImageElement>(null);

  useEffect(() => {
    const fetchCFGData = async () => {
      if (!jobId) return;

      try {
        setLoading(true);
        setError(null);

        // Fetch CFG metadata
        const response = await fetch(`${API_CONFIG.BASE_URL}/job/${jobId}/cfg`);
        
        if (!response.ok) {
          if (response.status === 404) {
            throw new Error("Control flow analysis not available for this job");
          }
          throw new Error(`Failed to fetch CFG data: ${response.statusText}`);
        }

        const data = await response.json();
        setCfgData(data);

        // Set image URL for the CFG PNG
        setImageUrl(`${API_CONFIG.BASE_URL}/job/${jobId}/cfg/image`);
      } catch (err) {
        console.error("Error fetching CFG data:", err);
        setError(err instanceof Error ? err.message : "Failed to load CFG data");
      } finally {
        setLoading(false);
      }
    };

    fetchCFGData();
  }, [jobId]);

  const handleDownloadImage = () => {
    if (imageUrl) {
      const link = document.createElement('a');
      link.href = imageUrl;
      link.download = `cfg_${jobId}.png`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  const handleZoomIn = () => {
    setZoom((prev) => Math.min(prev + 0.25, 4));
  };

  const handleZoomOut = () => {
    setZoom((prev) => Math.max(prev - 0.25, 0.5));
  };

  const handleResetZoom = () => {
    setZoom(1);
  };

  const parseAnalysisOutput = (output: string) => {
    if (!output) return [];
    
    // Split into sections based on numbered headers like [1], [2], etc.
    const sections = output.split(/\n(?=\[\d+\])/);
    
    return sections.map((section, index) => {
      const lines = section.split('\n');
      const title = lines[0]?.trim() || `Section ${index + 1}`;
      const content = lines.slice(1).join('\n').trim();
      
      return { title, content };
    });
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-cyber-dark via-gray-900 to-black">
        <Navbar />
        <div className="container mx-auto px-4 py-8">
          <div className="flex items-center justify-center h-64">
            <div className="text-cyber-cyan text-xl animate-pulse">Loading CFG data...</div>
          </div>
        </div>
        <Footer />
      </div>
    );
  }

  if (error || !cfgData) {
    // Parse error message to provide helpful guidance
    const isRadare2Missing = error?.includes("radare2") || error?.includes("exit code 127");
    const isGraphVizMissing = error?.includes("GraphViz") || error?.includes(".dot files found");
    const isDirEmpty = error?.includes("empty") || error?.includes("no visualization files");
    
    return (
      <div className="min-h-screen bg-gradient-to-br from-cyber-dark via-gray-900 to-black">
        <Navbar />
        <div className="container mx-auto px-4 py-8">
          <Card className="bg-gray-800/50 border-red-500/50">
            <CardHeader>
              <CardTitle className="text-red-500 flex items-center gap-2">
                <AlertTriangle className="h-6 w-6" />
                CFG Visualization Not Available
              </CardTitle>
              <CardDescription className="text-gray-400 mt-2">
                {error || "Unknown error"}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Specific error guidance */}
              {isRadare2Missing && (
                <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-4">
                  <h4 className="text-yellow-400 font-semibold mb-2">Missing Dependency: radare2</h4>
                  <p className="text-sm text-gray-300 mb-3">
                    The control flow analysis requires radare2 to be installed on the backend server.
                  </p>
                  <code className="block bg-black/50 p-3 rounded text-xs text-cyan-400 font-mono">
                    # Install radare2<br/>
                    sudo apt-get install radare2<br/>
                    <br/>
                    # Or build from source<br/>
                    git clone https://github.com/radareorg/radare2<br/>
                    cd radare2 && sys/install.sh
                  </code>
                </div>
              )}
              
              {isGraphVizMissing && (
                <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-4">
                  <h4 className="text-yellow-400 font-semibold mb-2">Missing Dependency: GraphViz</h4>
                  <p className="text-sm text-gray-300 mb-3">
                    DOT files were generated but PNG conversion failed. GraphViz may not be installed.
                  </p>
                  <code className="block bg-black/50 p-3 rounded text-xs text-cyan-400 font-mono">
                    # Install GraphViz<br/>
                    sudo apt-get install graphviz
                  </code>
                </div>
              )}
              
              {isDirEmpty && !isRadare2Missing && !isGraphVizMissing && (
                <div className="bg-orange-500/10 border border-orange-500/30 rounded p-4">
                  <h4 className="text-orange-400 font-semibold mb-2">Analysis Incomplete</h4>
                  <p className="text-sm text-gray-300">
                    The CFG analysis started but didn't produce any output files. The analysis may have failed or been interrupted.
                  </p>
                </div>
              )}
              
              <div className="flex gap-3">
                <Button onClick={() => navigate(`/job/${jobId}`)} variant="outline">
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Back to Job Details
                </Button>
                <Button 
                  onClick={() => window.location.reload()} 
                  variant="outline"
                  className="text-cyber-cyan border-cyber-cyan/50"
                >
                  Retry
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
        <Footer />
      </div>
    );
  }

  const sections = parseAnalysisOutput(cfgData.analysis_output);

  return (
    <div className="min-h-screen bg-gradient-to-br from-cyber-dark via-gray-900 to-black">
      <Navbar />
      
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-6">
          <Button 
            onClick={() => navigate(`/job/${jobId}`)} 
            variant="ghost"
            className="mb-4 text-cyber-cyan hover:text-cyber-cyan/80"
          >
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Job Details
          </Button>
          
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-3">
                <Network className="h-8 w-8 text-cyber-cyan" />
                Control Flow Graph
              </h1>
              <p className="text-gray-400">Job ID: {jobId}</p>
            </div>
            
            <div className="flex items-center gap-3">
              <Badge variant="outline" className="text-cyber-cyan border-cyber-cyan">
                {cfgData.architecture.toUpperCase()}
              </Badge>
              <Badge 
                variant={cfgData.status === "success" ? "default" : "secondary"}
                className={cfgData.status === "success" ? "bg-green-500/20 text-green-400" : ""}
              >
                {cfgData.status}
              </Badge>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* CFG Visualization - Main Column */}
          <div className="lg:col-span-2">
            <Card className="bg-gray-800/50 border-cyber-cyan/30">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-white flex items-center gap-2">
                    <Maximize2 className="h-5 w-5 text-cyber-cyan" />
                    Control Flow Visualization
                  </CardTitle>
                  <Button 
                    onClick={handleDownloadImage}
                    variant="outline"
                    size="sm"
                    className="text-cyber-cyan border-cyber-cyan/50 hover:bg-cyber-cyan/10"
                  >
                    <Download className="mr-2 h-4 w-4" />
                    Download Image
                  </Button>
                </div>
                <CardDescription className="text-gray-400">
                  Use mouse wheel to zoom, click and drag to pan
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="relative bg-black/50 rounded-lg border border-gray-700">
                  {/* Zoom Controls */}
                  <div className="absolute top-4 right-4 z-10 flex flex-col gap-2">
                    <Button
                      onClick={handleZoomIn}
                      size="icon"
                      variant="secondary"
                      className="bg-gray-800/90 hover:bg-gray-700"
                    >
                      <ZoomIn className="h-4 w-4" />
                    </Button>
                    <Button
                      onClick={handleZoomOut}
                      size="icon"
                      variant="secondary"
                      className="bg-gray-800/90 hover:bg-gray-700"
                    >
                      <ZoomOut className="h-4 w-4" />
                    </Button>
                    <Button
                      onClick={handleResetZoom}
                      size="icon"
                      variant="secondary"
                      className="bg-gray-800/90 hover:bg-gray-700"
                    >
                      <Maximize2 className="h-4 w-4" />
                    </Button>
                  </div>

                  {/* Image Container with scroll */}
                  <div 
                    ref={imageContainerRef}
                    className="overflow-auto"
                    style={{ height: "600px" }}
                  >
                    <img
                      ref={imageRef}
                      src={imageUrl}
                      alt="Control Flow Graph"
                      className="transition-transform duration-200"
                      style={{ 
                        transform: `scale(${zoom})`,
                        transformOrigin: "top left",
                        cursor: zoom > 1 ? "move" : "default"
                      }}
                    />
                  </div>
                </div>

                {/* Generated Files Info */}
                {cfgData.generated_files.cfg_png.length > 0 && (
                  <div className="mt-4 p-3 bg-gray-900/50 rounded border border-gray-700">
                    <p className="text-sm text-gray-400 mb-2">
                      Generated {cfgData.generated_files.cfg_png.length} CFG visualization(s)
                    </p>
                    <p className="text-xs text-gray-500">
                      Showing: {cfgData.latest_cfg_png.split('/').pop()}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Analysis Output - Side Column */}
          <div className="lg:col-span-1">
            <Card className="bg-gray-800/50 border-cyber-cyan/30 h-full">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Code2 className="h-5 w-5 text-cyber-cyan" />
                  Analysis Output
                </CardTitle>
                <CardDescription className="text-gray-400">
                  Radare2 control flow analysis results
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[600px] pr-4">
                  {sections.map((section, index) => (
                    <div key={index} className="mb-6">
                      <h3 className="text-cyber-cyan font-semibold mb-2 text-sm">
                        {section.title}
                      </h3>
                      <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono bg-black/30 p-3 rounded border border-gray-700 overflow-x-auto">
                        {section.content}
                      </pre>
                      {index < sections.length - 1 && <Separator className="my-4 bg-gray-700" />}
                    </div>
                  ))}

                  {/* Exit Code Info */}
                  <div className="mt-6 p-3 bg-gray-900/50 rounded border border-gray-700">
                    <p className="text-xs text-gray-400">
                      Exit Code: <span className={cfgData.exit_code === 0 ? "text-green-400" : "text-red-400"}>
                        {cfgData.exit_code}
                      </span>
                    </p>
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  );
};

export default CFGView;
