import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { JobsProvider } from "./contexts/JobsContext";
import Home from "./pages/Home";
import HowItWorks from "./pages/HowItWorks";
import Upload from "./pages/Upload";
import Jobs from "./pages/Jobs";
import JobDetail from "./pages/JobDetail";
import JobAnalysis from "./pages/JobAnalysis";
import NotFound from "./pages/NotFound";
import { AnalysisDemo } from "./components/AnalysisDemo";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <JobsProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/how-it-works" element={<HowItWorks />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/jobs" element={<Jobs />} />
            <Route path="/job/:jobId" element={<JobDetail />} />
            <Route path="/job/:jobId/analysis" element={<JobAnalysis />} />
            <Route path="/demo" element={<AnalysisDemo />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </JobsProvider>
  </QueryClientProvider>
);

export default App;
