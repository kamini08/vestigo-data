import {
  FileCheck,
  AlertTriangle,
  XCircle,
  Clock,
  Filter,
  Search,
  Download,
  Eye,
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Navbar } from "@/components/Navbar";
import { Footer } from "@/components/Footer";
import { Badge } from "@/components/ui/badge";
import { useJobs } from "@/contexts/JobsContext";
import { useNavigate } from "react-router-dom";
import { useState, useEffect } from "react";
import { toast } from "sonner";

const Jobs = () => {
  const { jobs } = useJobs();
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const [filteredJobs, setFilteredJobs] = useState(jobs);

  useEffect(() => {
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      setFilteredJobs(
        jobs.filter(
          (job) =>
            job.fileName.toLowerCase().includes(query) ||
            job.hash.toLowerCase().includes(query) ||
            job.id.toLowerCase().includes(query)
        )
      );
    } else {
      setFilteredJobs(jobs);
    }
  }, [searchQuery, jobs]);

  const getSeverityColor = (severity: string | null) => {
    switch (severity) {
      case "critical":
        return "bg-red-500/10 text-red-500 border-red-500/20";
      case "high":
        return "bg-orange-500/10 text-orange-500 border-orange-500/20";
      case "low":
        return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
      case "safe":
        return "bg-green-500/10 text-green-500 border-green-500/20";
      default:
        return "bg-primary/10 text-primary border-primary/20";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "complete":
        return <FileCheck className="w-5 h-5" />;
      case "analyzing":
        return <Clock className="w-5 h-5 animate-pulse" />;
      case "failed":
        return <XCircle className="w-5 h-5" />;
      default:
        return <Clock className="w-5 h-5" />;
    }
  };

  const getTimeAgo = (timestamp: string) => {
    const now = Date.now();
    const then = new Date(timestamp).getTime();
    const diff = now - then;

    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);

    if (minutes < 1) return "Just now";
    if (minutes < 60) return `${minutes} minute${minutes > 1 ? "s" : ""} ago`;
    if (hours < 24) return `${hours} hour${hours > 1 ? "s" : ""} ago`;
    return new Date(timestamp).toLocaleDateString();
  };

  const handleViewJob = (jobId: string) => {
    navigate(`/job/${jobId}`);
  };

  const handleDownloadReport = (job: any) => {
    const report = {
      jobId: job.id,
      fileName: job.fileName,
      hash: job.hash,
      status: job.status,
      severity: job.severity,
      cryptoFindings: job.threats,
      uploadTime: job.uploadTime,
      analysisTime: job.analysisTime,
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vestigo-report-${job.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Firmware analysis report downloaded successfully");
  };

  const handleExport = () => {
    const csvContent = [
      [
        "Job ID",
        "Firmware Name",
        "Hash",
        "Status",
        "Severity",
        "Crypto Findings",
        "Upload Time",
      ].join(","),
      ...filteredJobs.map((job) =>
        [
          job.id,
          job.fileName,
          job.hash,
          job.status,
          job.severity || "N/A",
          job.threats !== null ? job.threats : "N/A",
          job.uploadTime,
        ].join(",")
      ),
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vestigo-analysis-jobs.csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success("Analysis data exported successfully");
  };

  const stats = {
    total: jobs.length,
    inProgress: jobs.filter((j) => j.status === "analyzing").length,
    threats: jobs.reduce((sum, j) => sum + (j.threats || 0), 0),
    safe: jobs.filter((j) => j.severity === "safe").length,
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <section className="pt-32 pb-20 px-6">
        <div className="container mx-auto">
          {/* Header */}
          <div className="mb-12">
            <h1 className="text-5xl md:text-6xl font-display font-bold mb-6">
              Firmware Analysis Dashboard
            </h1>
            <p className="text-xl text-muted-foreground max-w-3xl">
              Track, inspect, and manage all firmware cryptographic analysis
              jobs performed through{" "}
              <span className="text-primary font-semibold">Vestigo</span>.
            </p>
          </div>

          {/* Stats Overview */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            {[
              {
                label: "Total Firmware Scans",
                value: stats.total.toString(),
                icon: FileCheck,
                color: "text-primary",
              },
              {
                label: "In Analysis",
                value: stats.inProgress.toString(),
                icon: Clock,
                color: "text-primary",
              },
              {
                label: "Crypto Findings Detected",
                value: stats.threats.toString(),
                icon: AlertTriangle,
                color: "text-red-500",
              },
              {
                label: "Verified Safe Binaries",
                value: stats.safe.toString(),
                icon: FileCheck,
                color: "text-green-500",
              },
            ].map((stat, index) => (
              <Card key={index} className="bg-card border-border p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">
                      {stat.label}
                    </p>
                    <p className="text-3xl font-display font-bold">
                      {stat.value}
                    </p>
                  </div>
                  <div
                    className={`w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center ${stat.color}`}
                  >
                    <stat.icon className="w-6 h-6" />
                  </div>
                </div>
              </Card>
            ))}
          </div>

          {/* Filters & Search */}
          <Card className="bg-card border-border p-6 mb-8">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search firmware by name, hash, or job ID..."
                  className="pl-10 bg-secondary border-border"
                />
              </div>
              <div className="flex gap-2">
                <Button variant="outline" className="border-border">
                  <Filter className="w-4 h-4 mr-2" />
                  Filter
                </Button>
                <Button
                  onClick={handleExport}
                  variant="outline"
                  className="border-border"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export
                </Button>
              </div>
            </div>
          </Card>

          {/* Jobs Table */}
          <Card className="bg-card border-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-secondary/50">
                  <tr>
                    <th className="text-left p-4 font-semibold">Job ID</th>
                    <th className="text-left p-4 font-semibold">
                      Firmware Name
                    </th>
                    <th className="text-left p-4 font-semibold">Status</th>
                    <th className="text-left p-4 font-semibold">Severity</th>
                    <th className="text-left p-4 font-semibold">
                      Crypto Findings
                    </th>
                    <th className="text-left p-4 font-semibold">Uploaded</th>
                    <th className="text-left p-4 font-semibold">Actions</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredJobs.map((job, index) => (
                    <tr
                      key={index}
                      className="border-t border-border hover:bg-secondary/30 transition-colors"
                    >
                      <td className="p-4">
                        <span className="font-mono text-sm text-primary">
                          {job.id}
                        </span>
                      </td>
                      <td className="p-4">
                        <div>
                          <p className="font-medium">{job.fileName}</p>
                          <p className="text-xs text-muted-foreground font-mono">
                            {job.hash.slice(0, 16)}...
                          </p>
                        </div>
                      </td>

                      <td className="p-4">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(job.status)}
                          <span className="capitalize">{job.status}</span>
                        </div>
                      </td>

                      <td className="p-4">
                        {job.severity ? (
                          <Badge
                            variant="outline"
                            className={`capitalize ${getSeverityColor(
                              job.severity
                            )}`}
                          >
                            {job.severity}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </td>

                      <td className="p-4">
                        {job.threats !== null ? (
                          <span
                            className={`font-semibold ${
                              job.threats > 0
                                ? "text-red-500"
                                : "text-green-500"
                            }`}
                          >
                            {job.threats}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </td>

                      <td className="p-4 text-muted-foreground">
                        {getTimeAgo(job.uploadTime)}
                      </td>

                      <td className="p-4">
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            className="border-border"
                            disabled={job.status === "analyzing"}
                            onClick={() => handleViewJob(job.id)}
                          >
                            <Eye className="w-4 h-4 mr-1" />
                            View
                          </Button>

                          <Button
                            size="sm"
                            variant="outline"
                            className="border-border"
                            disabled={job.status === "analyzing"}
                            onClick={() => handleDownloadReport(job)}
                          >
                            <Download className="w-4 h-4" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="p-4 border-t border-border flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                Showing {filteredJobs.length} of {jobs.length} firmware scans
              </p>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" className="border-border" disabled>
                  Previous
                </Button>
                <Button variant="outline" size="sm" className="border-border" disabled>
                  Next
                </Button>
              </div>
            </div>
          </Card>
        </div>
      </section>

      <Footer />
    </div>
  );
};

export default Jobs;















