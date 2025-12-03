import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

export interface FileUpload {
  id: string;
  name: string;
  size: number;
  progress: number;
  status: 'pending' | 'uploading' | 'processing' | 'complete';
}

export interface Job {
  id: string;
  fileName: string;
  hash: string;
  status: 'analyzing' | 'complete' | 'failed';
  severity: 'critical' | 'high' | 'low' | 'safe' | null;
  threats: number | null;
  uploadTime: string;
  analysisTime: string | null;
  fileSize: string;
  fileType: string;
  detectedThreats?: Array<{
    name: string;
    type: string;
    severity: string;
    description: string;
  }>;
}

interface JobsContextType {
  jobs: Job[];
  addJobs: (files: FileUpload[]) => void;
  getJobById: (id: string) => Job | undefined;
}

const JobsContext = createContext<JobsContextType | undefined>(undefined);

export const JobsProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [jobs, setJobs] = useState<Job[]>(() => {
    const saved = localStorage.getItem('binary-analyzer-jobs');
    if (saved) {
      return JSON.parse(saved);
    }
    // Initial mock data
    return [
      {
        id: "JOB-2847",
        fileName: "suspicious_payload.exe",
        hash: "5d41402abc4b2a76b9719d911017c592",
        status: "complete",
        severity: "critical",
        threats: 8,
        uploadTime: new Date(Date.now() - 600000).toISOString(),
        analysisTime: "45s",
        fileSize: "2.4 MB",
        fileType: "PE32 Executable",
        detectedThreats: [
          { name: "Trojan.Generic", type: "Trojan", severity: "Critical", description: "Malicious payload detected" },
          { name: "Backdoor.Agent", type: "Backdoor", severity: "High", description: "Remote access capability" }
        ]
      },
      {
        id: "JOB-2846",
        fileName: "malware_sample.bin",
        hash: "098f6bcd4621d373cade4e832627b4f6",
        status: "complete",
        severity: "high",
        threats: 5,
        uploadTime: new Date(Date.now() - 1500000).toISOString(),
        analysisTime: "38s",
        fileSize: "1.8 MB",
        fileType: "Binary",
        detectedThreats: [
          { name: "Worm.Win32", type: "Worm", severity: "High", description: "Self-replicating code" }
        ]
      }
    ];
  });

  useEffect(() => {
    localStorage.setItem('binary-analyzer-jobs', JSON.stringify(jobs));
  }, [jobs]);

  const addJobs = (files: FileUpload[]) => {
    const newJobs: Job[] = files.map((file, index) => ({
      id: `JOB-${Math.floor(Math.random() * 9000) + 1000}`,
      fileName: file.name,
      hash: generateMockHash(),
      status: 'analyzing' as const,
      severity: null,
      threats: null,
      uploadTime: new Date().toISOString(),
      analysisTime: null,
      fileSize: formatFileSize(file.size),
      fileType: getFileType(file.name)
    }));

    setJobs(prev => [...newJobs, ...prev]);

    // Simulate analysis completion after random time
    newJobs.forEach((job, index) => {
      setTimeout(() => {
        setJobs(prev => prev.map(j => {
          if (j.id === job.id) {
            const severities: Array<'critical' | 'high' | 'low' | 'safe'> = ['critical', 'high', 'low', 'safe'];
            const severity = severities[Math.floor(Math.random() * severities.length)];
            const threats = severity === 'safe' ? 0 : Math.floor(Math.random() * 10) + 1;
            
            return {
              ...j,
              status: 'complete' as const,
              severity,
              threats,
              analysisTime: `${Math.floor(Math.random() * 40) + 20}s`,
              detectedThreats: threats > 0 ? generateMockThreats(threats) : []
            };
          }
          return j;
        }));
      }, (index + 1) * 3000 + Math.random() * 2000);
    });
  };

  const getJobById = (id: string) => {
    return jobs.find(job => job.id === id);
  };

  return (
    <JobsContext.Provider value={{ jobs, addJobs, getJobById }}>
      {children}
    </JobsContext.Provider>
  );
};

export const useJobs = () => {
  const context = useContext(JobsContext);
  if (!context) {
    throw new Error('useJobs must be used within JobsProvider');
  }
  return context;
};

// Helper functions
function generateMockHash(): string {
  return Array.from({ length: 32 }, () => 
    Math.floor(Math.random() * 16).toString(16)
  ).join('');
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function getFileType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase();
  const types: Record<string, string> = {
    'exe': 'PE32 Executable',
    'dll': 'PE32 DLL',
    'elf': 'ELF Binary',
    'bin': 'Binary',
    'apk': 'Android APK',
    'dex': 'Dalvik Executable',
    'so': 'Shared Library',
    'o': 'Object File'
  };
  return types[ext || ''] || 'Unknown';
}

function generateMockThreats(count: number) {
  const threatNames = ['Trojan.Generic', 'Backdoor.Agent', 'Worm.Win32', 'Ransomware.Crypt', 'Spyware.KeyLog'];
  const types = ['Trojan', 'Backdoor', 'Worm', 'Ransomware', 'Spyware'];
  const severities = ['Critical', 'High', 'Medium'];
  const descriptions = [
    'Malicious payload detected',
    'Remote access capability',
    'Self-replicating code',
    'File encryption behavior',
    'Keylogging activity'
  ];

  return Array.from({ length: Math.min(count, 5) }, (_, i) => ({
    name: threatNames[i % threatNames.length],
    type: types[i % types.length],
    severity: severities[i % severities.length],
    description: descriptions[i % descriptions.length]
  }));
}
