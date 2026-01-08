import { Injectable, signal } from '@angular/core';
import { Subject } from 'rxjs';

export type LogLevel = 'INFO' | 'WARN' | 'ERROR' | 'DEBUG' | 'SYSTEM';

export interface LogEntry {
  timestamp: Date;
  level: LogLevel;
  source: string;
  message: string;
  data?: any;
}

@Injectable({
  providedIn: 'root'
})
export class LoggingService {
  private logs = signal<LogEntry[]>([]);
  // Observable for critical system alerts (for UI display)
  public systemAlert$ = new Subject<LogEntry>();

  info(source: string, message: string, data?: any) {
    this.addLog('INFO', source, message, data);
  }

  warn(source: string, message: string, data?: any) {
    this.addLog('WARN', source, message, data);
  }

  error(source: string, message: string, error?: any) {
    this.addLog('ERROR', source, message, error);
  }

  debug(source: string, message: string, data?: any) {
    this.addLog('DEBUG', source, message, data);
  }
  
  system(message: string, data?: any) {
      this.addLog('SYSTEM', 'KERNEL', message, data);
  }

  private addLog(level: LogLevel, source: string, message: string, data?: any) {
    const entry: LogEntry = {
      timestamp: new Date(),
      level,
      source,
      message,
      data
    };
    
    // Console output with styling
    const style = this.getStyle(level);
    if (data) {
        console.log(`%c[${level}] [${source}] ${message}`, style, data);
    } else {
        console.log(`%c[${level}] [${source}] ${message}`, style);
    }

    // Store in internal log signal (limited size to prevent memory leaks)
    this.logs.update(current => {
        const newLogs = [...current, entry];
        if (newLogs.length > 2000) newLogs.shift();
        return newLogs;
    });

    // Notify UI subscribers for SYSTEM level events (Critical/Global Errors)
    if (level === 'SYSTEM') {
        this.systemAlert$.next(entry);
    }
  }

  getLogs() {
      return this.logs.asReadonly();
  }

  getFormattedLogs(): string {
      return this.logs().map(log => {
          const meta = log.data ? ` | DATA: ${JSON.stringify(log.data)}` : '';
          return `[${log.timestamp.toISOString()}] [${log.level}] [${log.source}] ${log.message}${meta}`;
      }).join('\n');
  }

  private getStyle(level: LogLevel): string {
      switch (level) {
          case 'ERROR': return 'color: #ef4444; font-weight: bold;';
          case 'WARN': return 'color: #f59e0b;';
          case 'INFO': return 'color: #3b82f6;';
          case 'DEBUG': return 'color: #6b7280;';
          case 'SYSTEM': return 'color: #10b981; font-weight: bold;';
          default: return '';
      }
  }
}