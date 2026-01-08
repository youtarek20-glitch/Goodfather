import { ErrorHandler, Injectable, Injector } from '@angular/core';
import { LoggingService } from './logging.service';

@Injectable()
export class GlobalErrorHandler implements ErrorHandler {
  constructor(private injector: Injector) {}

  handleError(error: any) {
    // Lazy injection to prevent circular dependency during app initialization
    try {
        const logger = this.injector.get(LoggingService);
        
        let message = 'Unknown Error';
        let stack = null;
        let context = null;

        if (error instanceof Error) {
            message = error.message;
            stack = error.stack;
        } else if (typeof error === 'object') {
            message = error.message || error.toString();
            context = error;
        } else {
            message = error.toString();
        }

        // Filter out benign resize observer errors which are common in browser environments
        if (message.includes('ResizeObserver loop limit exceeded')) {
            return;
        }

        // Use 'system' level to trigger UI alert via LoggingService
        logger.system(`CRITICAL EXCEPTION: ${message}`, { stack, context });
    } catch (loggingError) {
        // Fallback if LoggingService itself fails or isn't available
        console.error('CRITICAL: LoggingService failed during error handling', loggingError);
        console.error('ORIGINAL ERROR:', error);
    }
  }
}