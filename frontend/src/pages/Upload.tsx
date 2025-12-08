import {
  Upload as UploadIcon,
  File,
  CheckCircle2,
  AlertCircle,
  Info,
  X,
  FolderOpen,
} from "lucide-react";

import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Navbar } from "@/components/Navbar";
import { Footer } from "@/components/Footer";
import { Progress } from "@/components/ui/progress";

import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { API_CONFIG } from "@/config/api";

interface UploadFile {
  id: string;
  file: File;
  progress: number;
  status: "pending" | "uploading" | "complete" | "failed";
}

const Upload = () => {
  const [dragActive, setDragActive] = useState(false);
  const [uploadFiles, setUploadFiles] = useState<UploadFile[]>([]);
  const [hashInput, setHashInput] = useState("");
  const [isUploading, setIsUploading] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const navigate = useNavigate();

  // DRAG + DROP HANDLERS -----------------------------------------------
  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();

    if (e.type === "dragenter" || e.type === "dragover") setDragActive(true);
    else if (e.type === "dragleave") setDragActive(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) handleFiles(files);
  };

  // FILE ADD HANDLER --------------------------------------------------
  const handleFiles = (files: File[]) => {
    const newFiles: UploadFile[] = files.map((file) => ({
      id: Math.random().toString(36).substring(7),
      file,
      progress: 0,
      status: "pending",
    }));

    setUploadFiles((prev) => [...prev, ...newFiles]);
    toast.success(`${files.length} file(s) added`);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) handleFiles(Array.from(e.target.files));
  };

  // REMOVE FILE -------------------------------------------------------
  const removeFile = (id: string) => {
    setUploadFiles((prev) => prev.filter((f) => f.id !== id));
  };

  // START REAL BACKEND UPLOAD -----------------------------------------
  const startUpload = async () => {
    if (uploadFiles.length === 0) {
      toast.error("No files selected");
      return;
    }

    setIsUploading(true);

    for (const uploadFile of uploadFiles) {
      setUploadFiles((prev) =>
        prev.map((f) =>
          f.id === uploadFile.id ? { ...f, status: "uploading" } : f
        )
      );

      // FAKE PROGRESS (visual only)
      for (let p = 0; p <= 70; p += 10) {
        await new Promise((res) => setTimeout(res, 120));
        setUploadFiles((prev) =>
          prev.map((f) =>
            f.id === uploadFile.id ? { ...f, progress: p } : f
          )
        );
      }

      // REAL UPLOAD CALL
      const formData = new FormData();
      formData.append("file", uploadFile.file);

      try {
        const res = await fetch(`${API_CONFIG.BASE_URL}${API_CONFIG.ENDPOINTS.ANALYZE}`, {
          method: "POST",
          body: formData,
        });

        const data = await res.json();

        if (!res.ok || data.error) throw new Error("Upload failed");

        // Progress to 100%
        setUploadFiles((prev) =>
          prev.map((f) =>
            f.id === uploadFile.id ? { ...f, progress: 100, status: "complete" } : f
          )
        );

        // Handle response structure from backend
        const jobId = data.jobId;
        const analysisInfo = data.analysis || {};
        
        toast.success(`Upload successful! Analysis started for Job: ${jobId}`);
        
        // Show routing decision info
        if (analysisInfo.routing_decision) {
          toast.info(`Analysis Path: ${analysisInfo.routing_decision}`);
        }

        // Redirect to comprehensive analysis page
        navigate(`/job/${jobId}/analysis`);
        return;
      } catch (err) {
        console.error(err);
        toast.error("Upload failed");

        setUploadFiles((prev) =>
          prev.map((f) =>
            f.id === uploadFile.id ? { ...f, status: "failed" } : f
          )
        );
      }
    }

    setIsUploading(false);
  };

  // HASH ANALYSIS ----------------------------------------------------
  const handleHashAnalysis = () => {
    toast.error("Hash analysis is not supported in backend yet");
  };

  // RENDER ------------------------------------------------------------
  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <section className="pt-32 pb-20 px-6">
        <div className="container mx-auto max-w-4xl">
          {/* HEADER */}
          <div className="text-center mb-12">
            <h1 className="text-5xl md:text-6xl font-display font-bold mb-4">
              Upload Firmware for Crypto Analysis
            </h1>
            <p className="text-xl text-muted-foreground">
              Vestigo performs AES, RSA, ECC, SHA, XOR detection automatically.
            </p>
          </div>

          {/* UPLOAD BOX */}
          <Card
            className="bg-card border-border p-10"
            onDragEnter={handleDrag}
            onDragOver={handleDrag}
            onDragLeave={handleDrag}
            onDrop={handleDrop}
          >
            <div
              className={`border-2 border-dashed rounded-xl p-12 text-center transition-all ${
                dragActive ? "border-primary bg-primary/10" : "border-border"
              }`}
            >
              <UploadIcon className="w-14 h-14 mx-auto text-primary mb-4" />

              <p className="text-lg font-semibold">
                Drag & drop firmware files
              </p>

              <p className="text-muted-foreground mt-1 mb-6">
                OR click below to browse
              </p>

              <div className="flex justify-center gap-4">
                <Button onClick={() => fileInputRef.current?.click()}>
                  <File className="w-4 h-4 mr-2" />
                  Browse Files
                </Button>

                <Button
                  variant="outline"
                  onClick={() => folderInputRef.current?.click()}
                >
                  <FolderOpen className="w-4 h-4 mr-2" />
                  Browse Folder
                </Button>
              </div>

              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={handleFileSelect}
              />

              <input
                ref={folderInputRef}
                type="file"
                className="hidden"
                {...({ webkitdirectory: "", directory: "" } as any)}
                onChange={handleFileSelect}
              />
            </div>

            {/* SELECTED FILES */}
            {uploadFiles.length > 0 && (
              <div className="mt-8 space-y-3">
                {uploadFiles.map((file) => (
                  <Card
                    key={file.id}
                    className="bg-secondary/50 border-border p-4"
                  >
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-3">
                        <File className="w-5 h-5 text-primary" />
                        <div>
                          <p className="font-semibold">{file.file.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {(file.file.size / 1024 / 1024).toFixed(2)} MB
                          </p>
                        </div>
                      </div>

                      {!isUploading && file.status === "pending" && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => removeFile(file.id)}
                        >
                          <X className="w-4 h-4" />
                        </Button>
                      )}

                      {file.status === "complete" && (
                        <CheckCircle2 className="w-5 h-5 text-green-500" />
                      )}
                    </div>

                    {file.status !== "pending" && (
                      <div className="mt-2">
                        <Progress value={file.progress} className="h-2" />
                      </div>
                    )}
                  </Card>
                ))}

                {!isUploading && (
                  <Button
                    className="w-full mt-2 bg-primary"
                    onClick={startUpload}
                  >
                    Start Analysis
                  </Button>
                )}
              </div>
            )}

            {/* DIVIDER */}
            <div className="my-12 flex items-center">
              <div className="flex-1 border-t border-border" />
              <span className="mx-6 text-muted-foreground">OR</span>
              <div className="flex-1 border-t border-border" />
            </div>

            {/* HASH ANALYSIS */}
            <Label className="font-semibold">Analyze File Hash</Label>

            <div className="flex gap-3 mt-2">
              <Input
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                placeholder="Enter MD5 / SHA-1 / SHA-256 hash"
                className="bg-secondary"
              />

              <Button onClick={handleHashAnalysis}>Analyze</Button>
            </div>
          </Card>
        </div>
      </section>

      <Footer />
    </div>
  );
};

export default Upload;
