import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { 
  ChevronDown, 
  ChevronRight, 
  Copy, 
  Search, 
  Download,
  Eye,
  EyeOff,
  Filter,
} from 'lucide-react';

interface JsonViewerProps {
  data: unknown;
  title?: string;
  maxHeight?: string;
  searchable?: boolean;
  downloadable?: boolean;
}

export const JsonViewer: React.FC<JsonViewerProps> = ({
  data,
  title = "Raw Data",
  maxHeight = "600px",
  searchable = true,
  downloadable = true,
}) => {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [searchTerm, setSearchTerm] = useState('');
  const [showOnlyMatches, setShowOnlyMatches] = useState(false);

  const toggleCollapse = (path: string) => {
    const newCollapsed = new Set(collapsed);
    if (newCollapsed.has(path)) {
      newCollapsed.delete(path);
    } else {
      newCollapsed.add(path);
    }
    setCollapsed(newCollapsed);
  };

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
      // Could add toast notification here
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const downloadJson = () => {
    const jsonString = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${title.replace(/\s+/g, '_').toLowerCase()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const highlightSearchTerm = (text: string): JSX.Element => {
    if (!searchTerm) return <span>{text}</span>;
    
    const parts = text.split(new RegExp(`(${searchTerm})`, 'gi'));
    return (
      <span>
        {parts.map((part, index) =>
          part.toLowerCase() === searchTerm.toLowerCase() ? (
            <mark key={index} className="bg-yellow-200 px-1 rounded">
              {part}
            </mark>
          ) : (
            <span key={index}>{part}</span>
          )
        )}
      </span>
    );
  };

  const shouldShowItem = (key: string, value: unknown, path: string): boolean => {
    if (!searchTerm || !showOnlyMatches) return true;
    
    const searchLower = searchTerm.toLowerCase();
    const keyMatches = key.toLowerCase().includes(searchLower);
    const valueMatches = typeof value === 'string' && value.toLowerCase().includes(searchLower);
    const pathMatches = path.toLowerCase().includes(searchLower);
    
    return keyMatches || valueMatches || pathMatches;
  };

  const renderJsonValue = (
    key: string,
    value: unknown,
    path: string = '',
    depth: number = 0
  ): JSX.Element => {
    const currentPath = path ? `${path}.${key}` : key;
    const isCollapsed = collapsed.has(currentPath);
    const indentClass = `ml-${Math.min(depth * 4, 16)}`;

    if (!shouldShowItem(key, value, currentPath) && showOnlyMatches) {
      return <React.Fragment key={currentPath} />;
    }

    if (value === null) {
      return (
        <div key={currentPath} className={`${indentClass} flex items-center gap-2 py-1`}>
          <span className="text-blue-600 font-medium">{highlightSearchTerm(`"${key}"`)}</span>
          <span className="text-gray-500">:</span>
          <span className="text-red-500 italic">null</span>
        </div>
      );
    }

    if (typeof value === 'boolean') {
      return (
        <div key={currentPath} className={`${indentClass} flex items-center gap-2 py-1`}>
          <span className="text-blue-600 font-medium">{highlightSearchTerm(`"${key}"`)}</span>
          <span className="text-gray-500">:</span>
          <span className={value ? 'text-green-600' : 'text-red-600'}>
            {value.toString()}
          </span>
        </div>
      );
    }

    if (typeof value === 'number') {
      return (
        <div key={currentPath} className={`${indentClass} flex items-center gap-2 py-1`}>
          <span className="text-blue-600 font-medium">{highlightSearchTerm(`"${key}"`)}</span>
          <span className="text-gray-500">:</span>
          <span className="text-purple-600 font-mono">{value}</span>
        </div>
      );
    }

    if (typeof value === 'string') {
      const isLongString = value.length > 100;
      const displayValue = isLongString && isCollapsed 
        ? `${value.substring(0, 100)}...` 
        : value;

      return (
        <div key={currentPath} className={`${indentClass} flex items-start gap-2 py-1`}>
          {isLongString && (
            <Button
              variant="ghost"
              size="sm"
              className="h-4 w-4 p-0 flex-shrink-0"
              onClick={() => toggleCollapse(currentPath)}
            >
              {isCollapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </Button>
          )}
          <span className="text-blue-600 font-medium">{highlightSearchTerm(`"${key}"`)}</span>
          <span className="text-gray-500">:</span>
          <span className="text-green-600 font-mono break-all">
            "{highlightSearchTerm(displayValue)}"
          </span>
        </div>
      );
    }

    if (Array.isArray(value)) {
      return (
        <div key={currentPath} className={indentClass}>
          <div className="flex items-center gap-2 py-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-4 w-4 p-0"
              onClick={() => toggleCollapse(currentPath)}
            >
              {isCollapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </Button>
            <span className="text-blue-600 font-medium">{highlightSearchTerm(`"${key}"`)}</span>
            <span className="text-gray-500">:</span>
            <Badge variant="outline" className="text-xs">
              Array [{value.length}]
            </Badge>
          </div>
          {!isCollapsed && (
            <div className="ml-4">
              {value.map((item, index) => 
                renderJsonValue(`[${index}]`, item, currentPath, depth + 1)
              )}
            </div>
          )}
        </div>
      );
    }

    if (typeof value === 'object' && value !== null) {
      const objectKeys = Object.keys(value as Record<string, unknown>);
      
      return (
        <div key={currentPath} className={indentClass}>
          <div className="flex items-center gap-2 py-1">
            <Button
              variant="ghost"
              size="sm"
              className="h-4 w-4 p-0"
              onClick={() => toggleCollapse(currentPath)}
            >
              {isCollapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </Button>
            <span className="text-blue-600 font-medium">{highlightSearchTerm(`"${key}"`)}</span>
            <span className="text-gray-500">:</span>
            <Badge variant="outline" className="text-xs">
              Object ({objectKeys.length})
            </Badge>
          </div>
          {!isCollapsed && (
            <div className="ml-4">
              {objectKeys.map(objKey =>
                renderJsonValue(objKey, (value as Record<string, unknown>)[objKey], currentPath, depth + 1)
              )}
            </div>
          )}
        </div>
      );
    }

    return (
      <div key={currentPath} className={`${indentClass} flex items-center gap-2 py-1`}>
        <span className="text-blue-600 font-medium">{highlightSearchTerm(`"${key}"`)}</span>
        <span className="text-gray-500">:</span>
        <span className="text-gray-600 italic">unknown type</span>
      </div>
    );
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>{title}</CardTitle>
          <div className="flex items-center gap-2">
            {downloadable && (
              <Button variant="outline" size="sm" onClick={downloadJson}>
                <Download className="h-4 w-4 mr-2" />
                Download
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={copyToClipboard}>
              <Copy className="h-4 w-4 mr-2" />
              Copy
            </Button>
          </div>
        </div>
        
        {searchable && (
          <div className="flex items-center gap-2 mt-4">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search in JSON..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-8"
              />
            </div>
            <Button
              variant={showOnlyMatches ? "default" : "outline"}
              size="sm"
              onClick={() => setShowOnlyMatches(!showOnlyMatches)}
              disabled={!searchTerm}
            >
              <Filter className="h-4 w-4 mr-2" />
              Filter
            </Button>
          </div>
        )}
      </CardHeader>
      <CardContent>
        <div 
          className={`font-mono text-sm bg-muted p-4 rounded-lg overflow-auto border`}
          style={{ maxHeight }}
        >
          {data && typeof data === 'object' ? (
            <div className="space-y-1">
              {Object.keys(data as Record<string, unknown>).map(key =>
                renderJsonValue(key, (data as Record<string, unknown>)[key])
              )}
            </div>
          ) : (
            <pre className="whitespace-pre-wrap break-words">
              {JSON.stringify(data, null, 2)}
            </pre>
          )}
        </div>
      </CardContent>
    </Card>
  );
};