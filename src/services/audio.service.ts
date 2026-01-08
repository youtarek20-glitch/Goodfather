import { Injectable, inject } from '@angular/core';
import { LoggingService } from './logging.service';

@Injectable({ providedIn: 'root' })
export class AudioService {
  private logger = inject(LoggingService);
  private audioCtx: AudioContext | null = null;
  private enabled = true;
  private initialized = false;

  constructor() {}

  /**
   * Initialize AudioContext on first user interaction to comply with browser autoplay policies.
   */
  init() {
    if (typeof window === 'undefined') return;
    if (this.initialized) {
        // Just ensure it's running if already initialized
        if (this.audioCtx && this.audioCtx.state === 'suspended') {
            this.audioCtx.resume().catch(e => this.logger.debug('Audio', 'Resume failed (benign)', e));
        }
        return;
    }

    try {
      const AudioContext = window.AudioContext || (window as any).webkitAudioContext;
      if (AudioContext) {
        this.audioCtx = new AudioContext();
        this.initialized = true;
        this.logger.info('Audio', 'AudioContext Initialized');
      } else {
          this.logger.warn('Audio', 'Web Audio API not supported.');
          this.enabled = false;
      }
    } catch (e) {
        this.logger.error('Audio', 'Failed to initialize AudioContext', e);
        this.enabled = false;
    }
  }

  toggle() {
    this.enabled = !this.enabled;
    this.logger.info('Audio', `Audio toggled: ${this.enabled}`);
    return this.enabled;
  }

  isEnabled() {
    return this.enabled;
  }

  playKeystroke() {
    if (!this.enabled || !this.audioCtx) return;

    try {
        const t = this.audioCtx.currentTime;
        const osc = this.audioCtx.createOscillator();
        const gain = this.audioCtx.createGain();

        // Mechanical click: High pitch square wave, extremely short
        osc.type = 'square';
        osc.frequency.setValueAtTime(800 + Math.random() * 200, t);
        osc.frequency.exponentialRampToValueAtTime(100, t + 0.03);

        gain.gain.setValueAtTime(0.03, t);
        gain.gain.exponentialRampToValueAtTime(0.001, t + 0.03);

        osc.connect(gain);
        gain.connect(this.audioCtx.destination);

        osc.start(t);
        osc.stop(t + 0.03);
    } catch (e) {
        // Log at DEBUG level to avoid console spam during rapid typing
        this.logger.debug('Audio', 'Keystroke sound playback failed', e);
    }
  }

  playEnter() {
    if (!this.enabled || !this.audioCtx) return;
    try {
        const t = this.audioCtx.currentTime;
        
        // Low thud for enter
        const osc = this.audioCtx.createOscillator();
        const gain = this.audioCtx.createGain();

        osc.type = 'triangle';
        osc.frequency.setValueAtTime(150, t);
        osc.frequency.exponentialRampToValueAtTime(40, t + 0.1);

        gain.gain.setValueAtTime(0.1, t);
        gain.gain.linearRampToValueAtTime(0, t + 0.1);

        osc.connect(gain);
        gain.connect(this.audioCtx.destination);

        osc.start(t);
        osc.stop(t + 0.1);
    } catch (e) {
        this.logger.debug('Audio', 'Enter sound playback failed', e);
    }
  }

  playAlert(type: 'SUCCESS' | 'ERROR' | 'BOOT') {
    if (!this.enabled || !this.audioCtx) return;
    try {
        const t = this.audioCtx.currentTime;
        const osc = this.audioCtx.createOscillator();
        const gain = this.audioCtx.createGain();

        osc.connect(gain);
        gain.connect(this.audioCtx.destination);

        if (type === 'SUCCESS') {
          // High tech chirp
          osc.type = 'sine';
          osc.frequency.setValueAtTime(1200, t);
          osc.frequency.linearRampToValueAtTime(2000, t + 0.1);
          gain.gain.setValueAtTime(0.05, t);
          gain.gain.linearRampToValueAtTime(0, t + 0.1);
          osc.start(t);
          osc.stop(t + 0.1);
        } else if (type === 'ERROR') {
          // Buzz
          osc.type = 'sawtooth';
          osc.frequency.setValueAtTime(100, t);
          osc.frequency.linearRampToValueAtTime(50, t + 0.3);
          gain.gain.setValueAtTime(0.08, t);
          gain.gain.linearRampToValueAtTime(0, t + 0.3);
          osc.start(t);
          osc.stop(t + 0.3);
        } else if (type === 'BOOT') {
          // Power up sound
          osc.type = 'square';
          osc.frequency.setValueAtTime(50, t);
          osc.frequency.exponentialRampToValueAtTime(800, t + 1.5);
          gain.gain.setValueAtTime(0, t);
          gain.gain.linearRampToValueAtTime(0.05, t + 0.2);
          gain.gain.linearRampToValueAtTime(0, t + 1.5);
          osc.start(t);
          osc.stop(t + 1.5);
        }
    } catch (e) {
        this.logger.warn('Audio', 'PlayAlert failed', e);
    }
  }
}