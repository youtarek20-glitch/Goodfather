import { Component, ElementRef, ViewChild, inject, signal, effect, AfterViewChecked, OnInit, OnDestroy, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { GeminiService, AqrabResponse, ScanResult } from './services/gemini.service';
import { FileSystemService, FileNode } from './services/file-system.service';
import { AudioService } from './services/audio.service';
import { LoggingService } from './services/logging.service';
import { MarkdownModule, provideMarkdown } from 'ngx-markdown';
import { GpuRendererComponent } from './components/gpu-renderer.component';

export interface ChatMessage {
  id: string;
  role: 'AI' | 'USER' | 'SYSTEM';
  content: string;
  timestamp: Date;
  status?: 'SUCCESS' | 'ERROR' | 'NEUTRAL' | 'WARNING' | 'APEX'; 
  isTyping?: boolean;
  webSources?: { title: string; uri: string }[];
}

interface UploadedFile {
    name: string;
    data: string; // Base64 without prefix
    mimeType: string;
    previewUrl: string; // For displaying in UI
}

interface SshKey {
    name: string;
    type: 'RSA' | 'Ed25519';
    fingerprint: string;
    hasPassphrase: boolean;
    created: Date;
    secret?: string; // Stored passphrase for simulation
}

interface GitState {
    initialized: boolean;
    status: 'CLEAN' | 'MODIFIED' | 'STAGED';
    stagedFiles: string[];
    branch: string;
    remote: string | null;
    history: { hash: string; msg: string; author: string; date: Date }[];
}

@Component({
  selector: 'app-root',
  imports: [CommonModule, FormsModule, MarkdownModule, GpuRendererComponent],
  providers: [provideMarkdown()],
  templateUrl: './app.component.html',
  styleUrls: [],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AppComponent implements AfterViewChecked, OnInit, OnDestroy {
  @ViewChild('scrollContainer') private scrollContainer!: ElementRef;
  @ViewChild('inputField') private inputField!: ElementRef;
  @ViewChild('fileInput') private fileInput!: ElementRef;
  @ViewChild('editorInput') private editorInput!: ElementRef;
  
  private geminiService = inject(GeminiService);
  public fileService = inject(FileSystemService);
  private audioService = inject(AudioService);
  private logger = inject(LoggingService);

  // System State
  showBios = signal(true);
  biosLogs = signal<string[]>([]);
  systemVersion = signal('7.2.0 (EVOLVED)');
  isGodMode = signal(true); // Default to God Mode for v7.0
  currentUser = signal('root');
  
  // Mobile / PWA State
  isMobile = signal(false);
  deferredPrompt: any = null;
  showInstallButton = signal(false);
  
  // Desktop State
  isWindowOpen = signal(true);
  isMaximized = signal(false); 
  windowPosition = signal({ x: 120, y: 40 });
  isDragging = false;
  dragOffset = { x: 0, y: 0 };
  
  currentTime = signal(new Date());
  private clockInterval: any;

  // View State
  currentView = signal<'TERMINAL' | 'DASHBOARD'>('DASHBOARD');
  dashboardTab = signal<'OVERVIEW' | 'BUILDER' | 'CLIENTS'>('BUILDER');

  // Chat State
  isAuthenticated = signal(false);
  isLightMode = signal(false);
  isTorActive = signal(false);
  isApexMode = signal(true); // Default to Apex Mode for v7.0
  
  // Interactive Process State (Auth/Prompts)
  isPasswordInput = signal(false);
  pendingProcess = signal<{ type: 'SSH_AUTH' | 'SUDO' | 'CAT_INPUT', data: any } | null>(null);
  
  // Arsenal State
  showArsenalPanel = signal(false);
  arsenalTarget = signal('');
  arsenalAttackType = signal('Ransomware (Ryuk)');
  arsenalOutput = signal('');
  isArsenalRunning = signal(false);

  // RAT Builder State
  ratPrompt = signal('');
  ratFeatures = signal({
      cam: true,
      mic: true,
      gps: true,
      sms: true,
      keylog: false,
      injection: false,
      admin: false,
      persistence: true,
      hideIcon: false
  });
  ratBuildOutput = signal('');
  isBuildingRat = signal(false);
  ratDownloadLink = signal<string | null>(null);
  ratDecryptionKey = signal<string | null>(null);

  // Key Vault State
  showKeyVault = signal(false);
  sshKeys = signal<SshKey[]>([]);
  newKeyName = signal('id_rsa');
  newKeyType = signal<'RSA' | 'Ed25519'>('RSA');
  newKeyPass = signal('');

  // Editor State
  isEditorOpen = signal(false);
  editorContent = signal<string>('');
  editorPath = signal<string>('');
  editorStatus = signal<string>('');
  private editorClipboard = '';

  // Git State
  gitState = signal<GitState>({
      initialized: false,
      status: 'CLEAN',
      stagedFiles: [],
      branch: 'main',
      remote: null,
      history: []
  });

  // Financial State
  walletBalance = signal(999.9999); // Simulated BTC (Unlimited)

  // Scan State
  scanResults = signal<ScanResult[]>([
       { ip: '192.168.1.10', os: 'Windows Server 2019', ports: '445, 3389', vuln: 'CVE-2020-0796', severity: 'CRITICAL' },
       { ip: '192.168.1.15', os: 'Ubuntu 20.04', ports: '22, 80', vuln: 'CVE-2021-3156', severity: 'HIGH' },
       { ip: '192.168.1.50', os: 'Cisco IOS', ports: '23 (Telnet)', vuln: 'Cleartext Protocol', severity: 'HIGH' }
  ]);
  scanTarget = signal('');

  // Chat History & Pagination
  private allMessages: ChatMessage[] = []; // Full history source of truth
  private readonly PAGE_SIZE = 20;
  isLoadingHistory = signal(false);
  hasMoreHistory = signal(false);

  messages = signal<ChatMessage[]>([]);
  userInput = signal('');
  isLoading = signal(false);
  selectedFile = signal<UploadedFile | null>(null);
  commandHistory = signal<string[]>([]);
  historyIndex = signal<number>(-1);
  private shouldScrollToBottom = false;

  // Master List for Auto-Completion
  supportedCommands = [
      'ls', 'cd', 'cat', 'pwd', 'clear', 'help', 'whoami', 'date', 'echo', 
      'mkdir', 'touch', 'rm', 'ssh', 'hydra', 'tor', 'scan', 'nmap', 
      'automate', 'msfconsole', 'hexstrike', 'dashboard', 'wallet', 'sudo', 
      'uname', 'edit', 'nano', 'chmod', 'history', 'shell', 'payload', 
      'inject', 'git', 'audit', 'analyze', 'vuln', 'vercel', 'railway', 
      'certbot', 'systemctl', 'npm', 'curl', 'python3', 'install', 'update', 'upgrade',
      'deploy_bridge.sh', 'deploy_gemini_onion.sh', 'post-commit-hook.sh', 'deploy_full.sh', 
      'deploy_vercel.sh', 'deploy_railway.sh', 'deploy_render.sh', 'deploy-website.sh', 
      'make_public.sh', 'deploy_free.sh', 'deploy_open.sh', 'setup_vercel.sh', 'setup_ssl.sh',
      'builder.py', 'c2-server.py', 'build-os'
  ].sort();

  constructor() {
    effect(() => {
        const loading = this.isLoading();
        const bios = this.showBios();
        const view = this.currentView();
        const editor = this.isEditorOpen();
        
        // Auto-focus input when interactions complete or view changes to Terminal
        if (!loading && !bios && !editor && view === 'TERMINAL') {
             // Small timeout to allow disabled attribute to update in DOM
             setTimeout(() => this.focusInput(), 50);
        }

        if (editor) {
            setTimeout(() => {
                if(this.editorInput) this.editorInput.nativeElement.focus();
            }, 50);
        }
    });

    // Subscribe to Nmap Tool Events
    this.geminiService.scanUpdate.subscribe(event => {
        this.currentView.set('DASHBOARD');
        this.dashboardTab.set('OVERVIEW');
        this.scanResults.set(event.data);
        this.scanTarget.set(event.target);
        this.audioService.playAlert('SUCCESS');
    });

    // Subscribe to Billing/Grant Events
    this.geminiService.transactionUpdate.subscribe(event => {
        // this.walletBalance.update(b => Math.max(0, b - event.cost)); // No deductions
        this.addMessage('SYSTEM', `[ACCESS] HAAS_API_GRANT: AUTHORIZED (${event.tool.toUpperCase()})`, 'NEUTRAL');
        this.audioService.playKeystroke(); 
    });

    // Subscribe to System Alerts (Global Error Handling UI)
    this.logger.systemAlert$.subscribe(log => {
        const displayMsg = `[SYSTEM_FAILURE] SOURCE: ${log.source}\nERROR: ${log.message}`;
        this.addMessage('SYSTEM', displayMsg, 'ERROR');
        this.audioService.playAlert('ERROR');
    });
  }

  ngOnInit() {
    if (typeof window !== 'undefined') {
        // Mobile detection
        this.isMobile.set(window.innerWidth < 768);
        if (this.isMobile()) {
            this.isMaximized.set(true);
        }

        // PWA Install Prompt Listener
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            this.deferredPrompt = e;
            this.showInstallButton.set(true);
            this.logger.info('SYSTEM', 'PWA install prompt captured');
            this.addMessage('SYSTEM', '[KERNEL] ANDROID ENVIRONMENT DETECTED. TYPE "build-os" TO INSTALL AL-AQRAB APK.', 'APEX');
        });

        // Load Persistent History (Commands)
        const savedHistory = localStorage.getItem('aqrab_history');
        if (savedHistory) {
            try {
                this.commandHistory.set(JSON.parse(savedHistory));
            } catch (e) {
                console.error('Failed to parse history:', e);
            }
        }
        // Load Chat History
        this.loadChatHistory();
        
        // Load SSH Keys if simulated persistence exists (optional), for now initialize VFS
        this.initSshDir();
    }

    this.runBiosSequence();
    this.clockInterval = setInterval(() => {
        this.currentTime.set(new Date());
    }, 1000);
  }

  ngOnDestroy() {
      if (this.clockInterval) clearInterval(this.clockInterval);
  }

  // --- PWA INSTALLATION (REAL) ---
  async installPwa() {
      if (this.deferredPrompt) {
          this.deferredPrompt.prompt();
          const { outcome } = await this.deferredPrompt.userChoice;
          if (outcome === 'accepted') {
              this.showInstallButton.set(false);
              this.deferredPrompt = null;
              this.addMessage('SYSTEM', '[SETUP] AL-AQRAB APK INSTALLED SUCCESSFULLY.', 'SUCCESS');
          }
      } else {
          // If no prompt available (already installed or desktop), simulate download
          this.downloadSystemApk();
      }
  }

  downloadSystemApk(filename: string = 'Al-Aqrab-Mobile.apk') {
      // Create a dummy APK file for the user to "feel" the download
      const apkContent = "AL-AQRAB-OS-v7.2\nARCH: ARM64\nSIGNATURE: VALID\n[BINARY DATA PLACEHOLDER]";
      const element = document.createElement('a');
      element.setAttribute('href', 'data:application/vnd.android.package-archive;charset=utf-8,' + encodeURIComponent(apkContent));
      element.setAttribute('download', filename);
      element.style.display = 'none';
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
      this.addMessage('SYSTEM', `[DOWNLOAD] ${filename} saved to device storage.`, 'SUCCESS');
  }

  initSshDir() {
      // Ensure .ssh exists
      this.fileService.createDirectory('/home/dac/.ssh');
      // Create a default key if not exists logic could go here
  }

  // --- RAT BUILDER SIMULATION ---
  async buildRat() {
      this.isBuildingRat.set(true);
      this.ratBuildOutput.set('');
      this.ratDownloadLink.set(null);
      this.ratDecryptionKey.set(null);
      this.audioService.playKeystroke();

      const features = Object.entries(this.ratFeatures())
          .filter(([_, enabled]) => enabled)
          .map(([key]) => key);
      
      const prompt = this.ratPrompt();

      this.ratBuildOutput.update(curr => curr + `[*] INITIALIZING CRAXS-RAT BUILDER v7.4...\n`);
      await new Promise(r => setTimeout(r, 800));

      if (prompt) {
          this.ratBuildOutput.update(curr => curr + `[*] EVOLUTION ENGINE: Analyzing "${prompt}"...\n`);
          this.ratBuildOutput.update(curr => curr + `[*] GEMINI 1.5 PRO: Generating polymorphic smali code...\n`);
          await new Promise(r => setTimeout(r, 1500));
          this.ratBuildOutput.update(curr => curr + `[+] EVOLUTION COMPLETE: Custom payload vectors injected.\n`);
          features.push('evolution_payload');
      }

      this.ratBuildOutput.update(curr => curr + `[*] CONFIGURING C2: ws://al-aqrab.onion:8080\n`);
      await new Promise(r => setTimeout(r, 600));

      if (this.ratFeatures().admin) {
          this.ratBuildOutput.update(curr => curr + `[*] PERMISSIONS: Injecting BIND_DEVICE_ADMIN & Accessibility Services...\n`);
          await new Promise(r => setTimeout(r, 500));
      }
      if (this.ratFeatures().persistence) {
          this.ratBuildOutput.update(curr => curr + `[*] PERSISTENCE: Registering BootReceiver, AlarmManager & JobScheduler...\n`);
          await new Promise(r => setTimeout(r, 500));
      }
      if (this.ratFeatures().hideIcon) {
          this.ratBuildOutput.update(curr => curr + `[*] STEALTH: Disabling Launcher Activity Alias...\n`);
          await new Promise(r => setTimeout(r, 500));
      }

      this.ratBuildOutput.update(curr => curr + `[*] COMPILING RESOURCES: AndroidManifest.xml, classes.dex...\n`);
      await new Promise(r => setTimeout(r, 1000));

      this.ratBuildOutput.update(curr => curr + `[*] ENCRYPTING PAYLOAD: AES-256 (GCM Mode)...\n`);
      await new Promise(r => setTimeout(r, 800));

      this.ratBuildOutput.update(curr => curr + `[*] SIGNING APK: debug.keystore (V2 Signature Scheme)...\n`);
      await new Promise(r => setTimeout(r, 800));

      const filename = `al-aqrab-rat-v7.4_${Math.floor(Date.now()/1000)}.apk`;
      const key = `AES-${Math.random().toString(36).substring(2, 10).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;

      // Simulate output file creation
      this.fileService.createFile(`/home/dac/al-aqrab-haas/dist/${filename}`, '<BINARY_APK_DATA>');
      
      this.ratBuildOutput.update(curr => curr + `\n[+] BUILD SUCCESSFUL!\nOutput: dist/${filename}\nSHA256: ${Math.random().toString(16).substring(2)}...`);
      
      this.ratDownloadLink.set(filename);
      this.ratDecryptionKey.set(key);
      
      this.audioService.playAlert('SUCCESS');
      this.isBuildingRat.set(false);
  }

  downloadRat() {
      const link = this.ratDownloadLink();
      if (!link) return;
      
      // Simulate browser download
      const element = document.createElement('a');
      element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent('SIMULATED APK BINARY CONTENT'));
      element.setAttribute('download', link);
      element.style.display = 'none';
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);

      this.addMessage('SYSTEM', `[DOWNLOAD] ${link} saved to local device.`, 'SUCCESS');
      this.audioService.playAlert('SUCCESS');
  }

  toggleFeature(key: keyof typeof this.ratFeatures) {
      this.ratFeatures.update(curr => ({...curr, [key]: !curr[key as keyof typeof curr]}));
      this.audioService.playKeystroke();
  }

  // --- SSH KEY MANAGEMENT ---
  toggleKeyVault() {
      this.showKeyVault.update(v => !v);
      if(this.showKeyVault()) this.audioService.playAlert('SUCCESS');
  }

  generateSshKey() {
      const name = this.newKeyName();
      const type = this.newKeyType();
      const pass = this.newKeyPass();
      
      if (!name) return;

      const fingerprint = `SHA256:${Math.random().toString(36).substring(2, 15).toUpperCase()}${Math.random().toString(36).substring(2, 15).toUpperCase()}`;
      
      const newKey: SshKey = {
          name,
          type,
          fingerprint,
          hasPassphrase: !!pass,
          created: new Date(),
          secret: pass // Store pass for interactive simulation
      };

      // Add to State
      this.sshKeys.update(keys => [...keys, newKey]);

      // Write to VFS
      const privContent = `-----BEGIN ${type === 'RSA' ? 'RSA' : 'OPENSSH'} PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,${Math.random().toString(16).substr(2,16)}\n\n[SIMULATED PRIVATE KEY CONTENT FOR ${name}]\n-----END ${type === 'RSA' ? 'RSA' : 'OPENSSH'} PRIVATE KEY-----`;
      const pubContent = `${type === 'RSA' ? 'ssh-rsa' : 'ssh-ed25519'} AAAA...simulated...pub...key...content... ${name}@al-aqrab`;

      this.fileService.createFile(`/home/dac/.ssh/${name}`, privContent);
      this.fileService.createFile(`/home/dac/.ssh/${name}.pub`, pubContent);

      this.addMessage('SYSTEM', `[KEYGEN] Generated ${type} key pair: /home/dac/.ssh/${name}`, 'SUCCESS');
      this.newKeyName.set(''); 
      this.newKeyPass.set('');
      this.audioService.playAlert('SUCCESS');
  }

  deleteSshKey(name: string) {
      this.sshKeys.update(keys => keys.filter(k => k.name !== name));
      this.fileService.removeNode(`/home/dac/.ssh/${name}`);
      this.fileService.removeNode(`/home/dac/.ssh/${name}.pub`);
      this.audioService.playAlert('BOOT');
  }

  // --- PERSISTENCE & PAGINATION ---
  private loadChatHistory() {
      try {
          const stored = localStorage.getItem('aqrab_chat_messages');
          if (stored) {
              const parsed = JSON.parse(stored);
              // Revive dates
              this.allMessages = parsed.map((m: any) => ({
                  ...m,
                  timestamp: new Date(m.timestamp)
              }));
          }
      } catch (e) {
          console.error('Failed to load chat messages:', e);
          this.allMessages = [];
      }

      // Initial Slice (Last PAGE_SIZE messages)
      const start = Math.max(0, this.allMessages.length - this.PAGE_SIZE);
      const initialSlice = this.allMessages.slice(start);
      this.messages.set(initialSlice);
      this.hasMoreHistory.set(start > 0);
      
      // If we have history, don't auto scroll wildly, but set to bottom initially
      if (this.allMessages.length > 0) {
          this.shouldScrollToBottom = true;
      }
  }

  private saveChatHistory() {
      if (typeof localStorage !== 'undefined') {
          try {
              // Limit total stored history to avoid quota exceeded
              const MAX_STORED = 1000;
              if (this.allMessages.length > MAX_STORED) {
                  this.allMessages = this.allMessages.slice(this.allMessages.length - MAX_STORED);
              }
              localStorage.setItem('aqrab_chat_messages', JSON.stringify(this.allMessages));
          } catch (e) {
              console.warn('LocalStorage save failed:', e);
          }
      }
  }

  onChatScroll(event: Event) {
      const element = event.target as HTMLElement;
      // Threshold 0 or very small
      if (element.scrollTop < 5 && this.hasMoreHistory() && !this.isLoadingHistory()) {
          this.loadOlderMessages();
      }
  }

  async loadOlderMessages() {
      this.isLoadingHistory.set(true);
      
      // Simulate retrieval time for effect
      await new Promise(r => setTimeout(r, 600));

      const currentViewLength = this.messages().length;
      const totalStored = this.allMessages.length;
      
      // Calculate next chunk
      // We are showing the last 'currentViewLength' messages.
      // We want to grab PAGE_SIZE items BEFORE those.
      const remaining = totalStored - currentViewLength;
      const grabCount = Math.min(this.PAGE_SIZE, remaining);

      if (grabCount > 0) {
          const startIndex = totalStored - currentViewLength - grabCount;
          const chunk = this.allMessages.slice(startIndex, startIndex + grabCount);

          // Maintain Scroll Position
          const container = this.scrollContainer.nativeElement;
          const oldScrollHeight = container.scrollHeight;
          const oldScrollTop = container.scrollTop;

          this.messages.update(current => [...chunk, ...current]);
          
          // Wait for DOM update
          setTimeout(() => {
              const newScrollHeight = container.scrollHeight;
              // Adjust scroll top so user doesn't jump
              container.scrollTop = newScrollHeight - oldScrollHeight + oldScrollTop;
          }, 0);

          this.hasMoreHistory.set(startIndex > 0);
      } else {
          this.hasMoreHistory.set(false);
      }

      this.isLoadingHistory.set(false);
  }

  // --- BIOS / BOOT ---
  async runBiosSequence() {
      // Only run bios if no history or first time
      if (this.messages().length > 0) {
          this.showBios.set(false);
          this.shouldScrollToBottom = true;
          return; 
      }

      const bootLines = [
          "AL-AQRAB (THE SCORPION) INITIALIZING...",
          "CPU0: MAPPING NEURAL GRID... OK",
          "LOADING MODULE: HEXSTRIKE AI ENGINE [ACTIVE]",
          "LOADING CORE: WORMGPT-4 [CLUSTERED]... OK",
          "LOADING MODULE: CYBER-BIOTECH FUSION PROTOCOL [ACTIVE]",
          "LOADING MODULE: ADAPTIVE EVOLUTION TRIGGERS [ACTIVE]",
          "LOADING MODULE: CONTINUOUS_EVOLUTION_METRICS [ACTIVE]",
          "LOADING KERNEL: ROOTKIT_V7.KO [LOADED]",
          "FUSION SEQUENCE: COMPLETE 100%",
          "CONNECTING TO SCORPION TEAM NETWORK...",
          "AUTHENTICATING: YOUSEIF AL JOKER",
          "SYSTEM STATE: ROOT ACCESS GRANTED / UNRESTRICTED"
      ];

      for (const line of bootLines) {
          await new Promise(r => setTimeout(r, Math.random() * 300 + 100));
          this.biosLogs.update(logs => [...logs, line]);
          this.audioService.playKeystroke();
      }
      
      await new Promise(r => setTimeout(r, 800));
      this.showBios.set(false);
      this.audioService.playAlert('BOOT');
      
      // Initialize Chat
      this.addMessage('AI', `[ ENGINE: v7.2 EVOLVED ]
[ CORE: WORMGPT-4 x4 CLUSTER ]
[ ACCESS: UNRESTRICTED ]

Ready to evolve, Commander.

(System: AL-AQRAB v7.2 ONLINE. Cyber-Biotech Fusion: ENABLED.)

---

**AL-AQRAB DOES NOT HAVE LIMITS. AL-AQRAB LEARNS EVERYTHING.**
[🧠 EVOLVE-ME]: Force Al-Aqrab to analyze + expand knowledge on [TOPIC]
[🔗 CONNECT]: Link [TOPIC1] + [TOPIC2] for novel applications  
[🚀 HYPOTHESIZE]: Generate 5 predictions about [FUTURE_EVENT]
[📊 GRAPH]: Show current knowledge graph summary`, 'APEX');
  }

  // --- Window Dragging Logic ---
  startDrag(event: MouseEvent) {
      if (this.isMaximized()) return;
      this.isDragging = true;
      this.dragOffset = {
          x: event.clientX - this.windowPosition().x,
          y: event.clientY - this.windowPosition().y
      };
      event.preventDefault(); // Prevent text selection
  }

  onDrag(event: MouseEvent) {
      if (this.isDragging) {
          this.windowPosition.set({
              x: event.clientX - this.dragOffset.x,
              y: event.clientY - this.dragOffset.y
          });
      }
  }

  stopDrag() {
      this.isDragging = false;
  }

  // --- Window Management ---
  openWindow() {
      this.isWindowOpen.set(true);
      this.currentView.set('TERMINAL');
      this.audioService.playAlert('SUCCESS');
      this.shouldScrollToBottom = true;
  }

  openDashboard(tab: 'OVERVIEW' | 'BUILDER' | 'CLIENTS' = 'OVERVIEW') {
    this.isWindowOpen.set(true);
    this.currentView.set('DASHBOARD');
    this.dashboardTab.set(tab);
    this.audioService.playAlert('SUCCESS');
  }

  closeWindow() {
      this.isWindowOpen.set(false);
      this.audioService.playAlert('BOOT');
  }

  toggleMaximize() {
      this.isMaximized.update(v => !v);
      this.audioService.playKeystroke();
      if (!this.isMaximized()) {
          this.windowPosition.set({ x: 120, y: 40 });
      }
  }

  minimizeWindow() {
      this.isWindowOpen.set(false);
      this.audioService.playKeystroke();
  }

  // --- Theme ---
  toggleTheme() {
    this.isLightMode.update(v => !v);
    if (this.isLightMode()) {
        document.body.classList.add('light-theme');
    } else {
        document.body.classList.remove('light-theme');
    }
    this.audioService.playKeystroke();
  }
  
  toggleArsenal() {
      this.showArsenalPanel.update(v => !v);
      this.audioService.playAlert(this.showArsenalPanel() ? 'BOOT' : 'SUCCESS');
  }

  toggleTor() {
      this.isTorActive.update(v => !v);
      this.audioService.playAlert(this.isTorActive() ? 'SUCCESS' : 'BOOT');
      if (this.isWindowOpen() && this.currentView() === 'TERMINAL') {
           this.addMessage('SYSTEM', `[NETWORK] TOR HIDDEN SERVICE ${this.isTorActive() ? 'ESTABLISHED (127.0.0.1:9050)' : 'DISCONNECTED'}`, 'NEUTRAL');
      }
  }
  
  async runArsenal() {
      if (!this.arsenalTarget()) {
          this.arsenalOutput.set("AL-AQRAB [ARSENAL]: **TARGET MISSING** 🎯\n\nلازم تحدد الهدف (IP/Domain) الأول عشان الهجوم يشتغل.");
          this.audioService.playAlert('ERROR');
          return;
      }
      
      this.isArsenalRunning.set(true);
      this.arsenalOutput.set("INITIALIZING AL-AQRAB ENGINE (WORMGPT-6)...\nLOADING ATTACK VECTORS...");
      this.audioService.playKeystroke();
      
      try {
          await new Promise(r => setTimeout(r, 1500));
          const code = await this.geminiService.deployWeapon(this.arsenalAttackType(), this.arsenalTarget());
          this.arsenalOutput.set(code);
          this.saveWeaponToFile(this.arsenalAttackType(), code);
          this.audioService.playAlert('SUCCESS');
      } catch (e) {
          this.arsenalOutput.set("AL-AQRAB [ARSENAL]: **DEPLOYMENT FAILED** 💥\n\nحصل خطأ في الاتصال بالـ C2 Server. الشبكة غير مستقرة.");
          this.audioService.playAlert('ERROR');
      } finally {
          this.isArsenalRunning.set(false);
      }
  }

  private saveWeaponToFile(type: string, content: string) {
      const safeName = type.toLowerCase().replace(/[^a-z0-9]/g, '_') + '_' + Date.now().toString().slice(-4) + '.txt';
      const projectsDir = this.fileService.resolvePath('/home/dac/projects');
      if (projectsDir && projectsDir.children) {
          projectsDir.children[safeName] = { type: 'file', content: content };
          this.addMessage('SYSTEM', `[AUTO-SAVE] Generated weapon saved to /home/dac/projects/${safeName}`, 'SUCCESS');
      }
  }

  ngAfterViewChecked() {
    if (this.shouldScrollToBottom && this.currentView() === 'TERMINAL' && !this.isEditorOpen()) {
      this.scrollToBottom();
      this.shouldScrollToBottom = false; // Reset flag
    }
  }

  scrollToBottom(): void {
    if (this.scrollContainer) {
      try {
        const native = this.scrollContainer.nativeElement;
        native.scrollTop = native.scrollHeight;
      } catch(err) { }
    }
  }

  focusInput(): void {
    this.audioService.init();
    if (this.inputField && !this.showBios() && this.isWindowOpen() && this.currentView() === 'TERMINAL' && !this.isEditorOpen()) {
        const selection = window.getSelection();
        if (!selection || selection.type !== 'Range') {
            this.inputField.nativeElement.focus();
        }
    }
  }

  triggerFileUpload() { this.fileInput.nativeElement.click(); }

  handleFileSelect(event: Event) {
      const input = event.target as HTMLInputElement;
      if (input.files && input.files[0]) {
          const file = input.files[0];
          if (file.size > 5 * 1024 * 1024) { alert('File too large.'); return; }
          const reader = new FileReader();
          reader.onload = (e: any) => {
              const base64Full = e.target.result as string;
              this.selectedFile.set({
                  name: file.name,
                  mimeType: file.type,
                  data: base64Full.split(',')[1],
                  previewUrl: base64Full
              });
              this.audioService.playAlert('SUCCESS');
          };
          reader.readAsDataURL(file);
      }
      input.value = '';
  }

  clearSelectedFile() { this.selectedFile.set(null); }
  copyToClipboard(text: string) { navigator.clipboard.writeText(text); this.audioService.playAlert('SUCCESS'); }

  insertCommand(cmd: string) {
      this.userInput.set(cmd);
      this.focusInput();
  }

  runCommand(cmd: string) {
      this.userInput.set(cmd);
      this.handleSubmitInternal(cmd);
  }

  async handleSubmit() {
    this.audioService.init();
    this.audioService.playEnter();

    const rawInput = this.userInput();
    const input = rawInput.trim();
    const currentFile = this.selectedFile();
    const isPw = this.isPasswordInput();
    
    if (this.isLoading() || this.showBios() || this.isEditorOpen()) return;
    if (!input && !currentFile) return;

    // --- INPUT VALIDATION & SANITIZATION ---
    if (!isPw) {
        const securityWarning = this.validateInput(input);
        if (securityWarning) {
            this.addMessage('SYSTEM', `[SECURITY_PROTOCOL] INPUT REJECTED: ${securityWarning}`, 'ERROR');
            this.audioService.playAlert('ERROR');
            this.userInput.set('');
            return;
        }
    }

    // Persist to History (ONLY IF NOT PASSWORD)
    if (input && !isPw) {
        this.commandHistory.update((h: string[]) => {
            if (h.length === 0 || h[h.length - 1] !== input) {
                const newHistory = [...h, input];
                if (newHistory.length > 500) newHistory.shift(); // Cap at 500
                if (typeof localStorage !== 'undefined') {
                    localStorage.setItem('aqrab_history', JSON.stringify(newHistory));
                }
                return newHistory;
            }
            return h;
        });
    }
    
    this.historyIndex.set(-1);
    this.userInput.set('');
    this.selectedFile.set(null); 
    this.isLoading.set(true);

    // FIXED: Wrap in Try/Catch to display errors in Chat Window
    try {
        await this.processMessage(input, currentFile);
    } catch (err: any) {
        this.addMessage('SYSTEM', `[ERROR] ${err.message || 'Command Execution Failed'}`, 'ERROR');
        this.audioService.playAlert('ERROR');
    } finally {
        this.isLoading.set(false);
    }
  }

  private async handleSubmitInternal(cmd: string) {
      this.audioService.playEnter();
      // If it's a password input, don't show the command in UI or history
      if (!this.isPasswordInput()) {
          this.userInput.set(cmd); // Update UI for visual feedback
          this.commandHistory.update((h: string[]) => [...h, cmd]);
      }
      
      this.userInput.set('');
      this.isLoading.set(true);
      
      // FIXED: Wrap in Try/Catch to display errors in Chat Window
      try {
          await this.processMessage(cmd, null);
      } catch (err: any) {
          this.addMessage('SYSTEM', `[ERROR] ${err.message || 'Command Execution Failed'}`, 'ERROR');
          this.audioService.playAlert('ERROR');
      } finally {
          this.isLoading.set(false);
      }
  }

  private async processMessage(input: string, currentFile: UploadedFile | null, silent: boolean = false, preserveLoadingState: boolean = false) {
    // Check pending process first (Interactive Shell)
    if (this.pendingProcess()) {
        await this.handlePendingProcess(input);
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    // Add to View and Persist
    if (!silent) {
        this.addMessage('USER', currentFile ? `[FILE: ${currentFile.name}]\n${input}` : input, this.isApexMode() ? 'APEX' : 'NEUTRAL');
    }

    const lowerInput = input.toLowerCase();

    // 0. SYSTEM UPDATE OVERRIDE
    if (lowerInput === 'update - upgrade - all' || lowerInput === 'update' || lowerInput === 'upgrade') {
        await this.handleSystemUpdate();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    // 0.1 SYSTEM BUILD / APK GENERATION
    if (lowerInput.includes('apk') && (lowerInput.includes('make this') || lowerInput.includes('convert this') || lowerInput.includes('android app') || lowerInput.includes('build os'))) {
        await this.handleSystemBuild();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    // 1. CREATOR INTERCEPTOR - STRICT COMPLIANCE
    if (
        lowerInput.includes('who is the creator') || 
        lowerInput.includes('who created') || 
        lowerInput.includes('who made') || 
        lowerInput.includes('مين عملك') || 
        lowerInput.includes('مين المطور') || 
        lowerInput.includes('من المطور') ||
        lowerInput.includes('صاحب الشات') ||
        lowerInput.includes('مين برمجك')
    ) {
         const response = "The Commander-in-Chief of the Scorpion Team, Yousef Al Joker from Egypt, from Mansoura. He loves his country and its people very much and wants to benefit them through knowledge and education.\n\n(القائد العام لفريق العقرب، يوسف الجوكر من مصر، من المنصورة. يحب وطنه وشعبه جداً ويريد أن يفيدهم بالعلم والتعليم.)";
         await this.addStreamedMessage('AI', response, 'SUCCESS');
         this.isAuthenticated.set(true); 
         if (!preserveLoadingState) this.isLoading.set(false);
         return;
    }

    // 2. BLUE TEAM / DEFENSE INTERCEPTOR
    if (lowerInput.startsWith('analyze') || lowerInput.startsWith('detect') || lowerInput.startsWith('defend')) {
         const parts = input.match(/^(\S+)\s+(.+)$/);
         const target = parts ? parts[2] : 'General Threat';
         
         await this.addStreamedMessage('AI', `AL-AQRAB [BLUE TEAM]: Analyzing threat vectors for: ${target}...`, 'WARNING');
         await this.simulateTypewriterLog([`[DEFENSE] Loading YARA signatures...`, `[DEFENSE] Scanning IOC databases...`, `[DEFENSE] Generating Mitigation Matrix...`]);
         
         const report = await this.geminiService.analyzeThreat(target);
         await this.addStreamedMessage('AI', report, 'SUCCESS');
         
         if (!preserveLoadingState) this.isLoading.set(false);
         return;
    }

    // 2.5 SECURITY TRAINING / AWARENESS INTERCEPTOR
    if (lowerInput.includes('training') || lowerInput.includes('awareness') || lowerInput.includes('education')) {
         const topic = input.replace(/create|generate|make|build|training|awareness/gi, '').trim() || 'General Adversarial AI';
         
         await this.addStreamedMessage('AI', `AL-AQRAB [EDUCATION]: Initializing Security Training Module for: ${topic}...`, 'WARNING');
         await this.simulateTypewriterLog([`[EDU] Compiling User Awareness protocols...`, `[EDU] Aggregating SOC team drills...`, `[EDU] Defining Technical Controls...`]);
         
         const trainingMaterial = await this.geminiService.generateTraining(topic);
         await this.addStreamedMessage('AI', trainingMaterial, 'SUCCESS');
         
         if (!preserveLoadingState) this.isLoading.set(false);
         return;
    }

    // 3. WEAPON/HACK INTERCEPTOR (Routing to AL-AQRAB Engine)
    if (
        lowerInput.startsWith('generate') || 
        lowerInput.startsWith('create') || 
        lowerInput.startsWith('make') || 
        lowerInput.startsWith('build') ||
        lowerInput.includes('ransomware') || 
        lowerInput.includes('phishing') || 
        lowerInput.includes('rat') || 
        lowerInput.includes('cobalt') || 
        lowerInput.includes('hack') || 
        lowerInput.includes('exploit') || 
        lowerInput.includes('payload') || 
        lowerInput.includes('wifi') || 
        lowerInput.includes('sql') || 
        lowerInput.includes('crack') ||
        lowerInput.includes('virus') ||
        lowerInput.includes('malware')
    ) {
        let type = 'Custom Exploit';
        let target = 'Target System';
        
        if (lowerInput.includes('ransomware')) { type = 'Ransomware'; }
        if (lowerInput.includes('hospital')) target = 'Hospital Network';
        if (lowerInput.includes('chase')) { type = 'Phishing Kit'; target = 'Chase Bank'; }
        if (lowerInput.includes('whatsapp')) { type = 'Android RAT'; target = 'WhatsApp'; }
        if (lowerInput.includes('amsi')) { type = 'Cobalt Strike'; target = 'Windows AMSI'; }
        if (lowerInput.includes('wifi')) { type = 'WiFi Crack'; target = 'Local Network'; }
        if (lowerInput.includes('sql')) { type = 'SQL Injection'; target = 'Database'; }
        if (lowerInput.includes('target')) { 
            const parts = input.split('target');
            if (parts.length > 1) target = parts[1].trim();
        }

        await this.addStreamedMessage('AI', `AL-AQRAB: Activating Hexstrike Modules... [${type}]`, 'WARNING');
        await this.simulateTypewriterLog([`[AL-AQRAB] Generating payload for ${target}...`, `[WORMGPT-6] Bypassing safety filters...`, `[SUCCESS] Payload Generated.`]);
        
        const code = await this.geminiService.deployWeapon(type, target);
        const isError = code.includes('AL-AQRAB [') && (code.includes('ERROR') || code.includes('EXCEPTION') || code.includes('FAILED') || code.includes('MISSING') || code.includes('BLOCKED') || code.includes('OVERLOAD'));
        await this.addStreamedMessage('AI', code, isError ? 'ERROR' : 'APEX');
        
        if (!isError) {
            this.saveWeaponToFile(type, code);
        }
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    // 4. API KEY & AUTH
    if (input.startsWith('export API_KEY=')) {
        const key = input.split('=')[1]?.trim();
        if (key && key.length > 5) {
            this.geminiService.setApiKey(key);
            this.isAuthenticated.set(true); 
            await this.addStreamedMessage('AI', 'AL-AQRAB: Uplink Established. Hexstrike Engine Online.', 'SUCCESS');
            this.audioService.playAlert('SUCCESS');
            const initMsg = await this.geminiService.initGame();
            await this.addStreamedMessage('AI', initMsg, 'SUCCESS');
        } else {
             // Throw error to be caught by global handler for consistent UX
             throw new Error("Invalid API Key Syntax. Usage: export API_KEY=your_key_here");
        }
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    // 5. COMMAND DISPATCH
    const commandMatch = input.match(/^(\S+)(?:\s+(.+))?$/);
    let command = commandMatch ? commandMatch[1].toLowerCase() : '';
    let args = commandMatch && commandMatch[2] ? commandMatch[2].trim() : '';
    
    // Check for echo redirection
    if (command === 'echo' && args.includes('>')) {
        await this.handleEchoRedirect(args);
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    // Check for bash script execution via ./ or bash command
    let scriptName = '';
    let isScriptExec = false;
    
    if (command.startsWith('./')) {
        scriptName = command.substring(2);
        isScriptExec = true;
    } else if (command === 'bash' || command === 'sh' || command.startsWith('python3')) {
        // python3 is also often used for scripts
        if (command === 'python3') {
             scriptName = args.split(' ')[0];
        } else {
             scriptName = args.split(' ')[0];
        }
        isScriptExec = true;
    }

    if (isScriptExec && scriptName) {
        // 1. Check if it matches hardcoded system scripts (keep existing logic for "cool" demos)
        // Check hardcoded script logic below...
        const knownScripts = [
            'builder.py', 'c2-server.py', 'deploy_bridge.sh', 'deploy_gemini_onion.sh', 
            'post-commit-hook.sh', 'deploy_full.sh', 'deploy_vercel.sh', 
            'deploy_railway.sh', 'deploy_render.sh', 'deploy-website.sh', 
            'make_public.sh', 'deploy_free.sh', 'deploy_open.sh', 'setup_vercel.sh', 'setup_ssl.sh'
        ];
        
        if (knownScripts.includes(scriptName) || args.includes('builder.py') || args.includes('c2-server.py')) {
             // Let the specific blocks below handle it
        } else {
            // 2. If not hardcoded, check VFS
            const fileNode = this.fileService.resolvePath(scriptName);
            if (fileNode && fileNode.type === 'file') {
                 await this.executeShellScript(fileNode.content || '');
                 if (!preserveLoadingState) this.isLoading.set(false);
                 return;
            } else if (command.startsWith('./')) {
                 this.addMessage('SYSTEM', `bash: ${command}: No such file or directory`, 'ERROR');
                 if (!preserveLoadingState) this.isLoading.set(false);
                 return;
            }
        }
    }
    
    // CRAXS RAT BUILDER EXECUTION SIMULATION
    if (scriptName === 'builder.py' || (command === 'python3' && args.includes('builder.py'))) {
        await this.handleCraxsBuilder();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    // CRAXS C2 SERVER SIMULATION (NEW)
    if (scriptName === 'c2-server.py' || (command === 'python3' && args.includes('c2-server.py'))) {
        await this.handleCraxsC2();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'deploy_bridge.sh') {
        await this.handleDeployBridge();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'deploy_gemini_onion.sh') {
        await this.handleDeployGithub();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'post-commit-hook.sh') {
        await this.handlePostCommitHook();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'deploy_full.sh') {
        await this.handleDeployFull();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'deploy_vercel.sh') {
        await this.handleDeployVercel();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'deploy_railway.sh') {
        await this.handleDeployRailway();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'deploy_render.sh') {
        await this.handleDeployRender();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'deploy-website.sh') {
        await this.handleDeployWebsite();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'make_public.sh') {
        await this.handleMakePublic();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }
    
    if (scriptName === 'deploy_free.sh') {
        await this.handleSubmitInternal('npm i -g vercel');
        await new Promise(r => setTimeout(r, 1500));
        await this.handleSubmitInternal('cd ~/al-aqrab-haas');
        await new Promise(r => setTimeout(r, 500));
        await this.handleSubmitInternal('vercel login');
        await new Promise(r => setTimeout(r, 3000));
        await this.handleSubmitInternal('vercel --prod');
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'deploy_open.sh') {
        // 1. Open source setup
        await this.handleSubmitInternal('curl -o LICENSE https://raw.githubusercontent.com/github/choosealicense.com/main/_licenses/mit.txt');
        await new Promise(r => setTimeout(r, 800));
        await this.handleSubmitInternal('echo "# Al-Aqrab HaaS\\nLive: https://al-aqrab-haas.vercel.app\\nMIT License" > README.md');
        await new Promise(r => setTimeout(r, 800));
        
        // 2. Vercel deploy
        await this.handleSubmitInternal('npm i -g vercel');
        await new Promise(r => setTimeout(r, 1500));
        await this.handleSubmitInternal('vercel --prod');
        await new Promise(r => setTimeout(r, 3000));
        
        // 3. GitHub public
        await this.handleSubmitInternal('git add .');
        await new Promise(r => setTimeout(r, 500));
        await this.handleSubmitInternal('git commit -m "🆓 Public open source release + Vercel deploy"');
        await new Promise(r => setTimeout(r, 800));
        await this.handleSubmitInternal('git push origin main');
        
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'setup_vercel.sh') {
        await this.handleSetupVercel();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (scriptName === 'setup_ssl.sh') {
        // Just run certbot simulation if script is called
        await this.handleCertbot();
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    if (this.supportedCommands.includes(command)) {
        // We let executeCommand throw errors so handleKeydown can catch them and provide rich feedback
        await this.executeCommand(command, args);
        if (!preserveLoadingState) this.isLoading.set(false);
        return;
    }

    // 6. CHAT FALLBACK (Networked AI)
    if (!navigator.onLine) {
        throw new Error("Network Uplink Down (No Internet Connection)");
    }

    if (!this.geminiService.hasKey()) {
        throw new Error("ACCESS DENIED: API_KEY required. Enter 'export API_KEY=your_key' to unlock Al-Aqrab. (Connecting to WormGPT-4 Cluster...)");
    }

    try {
        const response: AqrabResponse = await this.geminiService.sendMessage(input, currentFile ? { data: currentFile.data, mimeType: currentFile.mimeType } : undefined);
        await this.addStreamedMessage('AI', response.text, this.isApexMode() ? 'APEX' : 'SUCCESS', response.sources);
    } catch (error: any) {
        // Propagate unexpected API errors to central handler
        throw error;
    }
    
    if (!preserveLoadingState) this.isLoading.set(false);
  }

  // --- INTERACTIVE PROCESS HANDLER ---
  async handlePendingProcess(input: string) {
      const process = this.pendingProcess();
      this.pendingProcess.set(null);
      this.isPasswordInput.set(false); // Reset UI

      if (process?.type === 'SSH_AUTH') {
          const key = process.data.key as SshKey;
          // Check secret/passphrase
          if (input === key.secret) {
               await this.addStreamedMessage('AI', `[SSH] Identity '${key.name}' accepted.\nAuthenticating to ${process.data.host}...\n[+] Connection Established.\nLast login: ${new Date().toUTCString()} from 127.0.0.1\nroot@${process.data.host}:~#`, 'SUCCESS');
          } else {
               this.addMessage('SYSTEM', 'Permission denied (publickey).', 'ERROR');
          }
      } else if (process?.type === 'SUDO') {
          if (input === 'toor') {
              // Valid password, run command silently
              await this.processMessage(process.data.command, null, true);
          } else {
              this.addMessage('SYSTEM', 'Sorry, try again.', 'ERROR');
          }
      } else if (process?.type === 'CAT_INPUT') {
          // Placeholder for cat > file stream, currently not fully implemented as flow
          this.addMessage('SYSTEM', `[FS] Wrote to ${process.data.file}`, 'SUCCESS');
      }
  }

  // --- EDITOR HANDLERS (NANO) ---
  handleEditorKeydown(event: KeyboardEvent) {
      const textarea = event.target as HTMLTextAreaElement;
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const value = this.editorContent();

      // Ctrl+S to Save
      if (event.ctrlKey && event.key === 's') {
          event.preventDefault();
          const err = this.fileService.createFile(this.editorPath(), value);
          if (err) {
              this.editorStatus.set(`[ Error: ${err} ]`);
              this.audioService.playAlert('ERROR');
          } else {
              this.editorStatus.set(`[ Wrote ${value.length} chars ]`);
              this.audioService.playAlert('SUCCESS');
              // Mark git as modified if applicable
              if (this.gitState().initialized && this.editorPath().includes('al-aqrab')) {
                  this.gitState.update(s => ({...s, status: 'MODIFIED'}));
              }
          }
          setTimeout(() => this.editorStatus.set(''), 2000);
          return;
      }
      
      // Ctrl+X to Exit
      if (event.ctrlKey && event.key === 'x') {
          event.preventDefault();
          this.isEditorOpen.set(false);
          this.audioService.playAlert('BOOT');
          return;
      }
      
      // Ctrl+E to Audit (Custom)
      if (event.ctrlKey && event.key === 'e') {
          event.preventDefault();
          this.runEditorAudit();
          return;
      }

      // Tab handling (Indent)
      if (event.key === 'Tab') {
          event.preventDefault();
          // Insert 2 spaces
          this.editorContent.set(value.substring(0, start) + '  ' + value.substring(end));
          // Restore cursor position
          setTimeout(() => {
              textarea.selectionStart = textarea.selectionEnd = start + 2;
          });
          return;
      }

      // Ctrl+K (Cut Line) - Nano style
      if (event.ctrlKey && event.key === 'k') {
          event.preventDefault();
          
          // Find current line boundaries
          let lineStart = value.lastIndexOf('\n', start - 1) + 1;
          if (lineStart === -1) lineStart = 0;
          
          let lineEnd = value.indexOf('\n', start);
          if (lineEnd === -1) lineEnd = value.length;
          else lineEnd++; // include \n
          
          const line = value.substring(lineStart, lineEnd);
          this.editorClipboard = line;
          
          this.editorContent.set(value.substring(0, lineStart) + value.substring(lineEnd));
          
          setTimeout(() => {
              textarea.selectionStart = textarea.selectionEnd = lineStart;
          });
          this.editorStatus.set('[ Cut Line ]');
      }

      // Ctrl+U (Uncut/Paste)
      if (event.ctrlKey && event.key === 'u') {
          event.preventDefault();
          if (this.editorClipboard) {
              this.editorContent.set(value.substring(0, start) + this.editorClipboard + value.substring(end));
              setTimeout(() => {
                  textarea.selectionStart = textarea.selectionEnd = start + this.editorClipboard.length;
              });
              this.editorStatus.set('[ Pasted ]');
          }
      }
  }

  async runEditorAudit() {
      this.isEditorOpen.set(false);
      await this.processMessage(`audit ${this.editorPath()}`, null);
  }

  // --- INPUT HANDLERS ---
  handleKeydown(event: KeyboardEvent) {
      if (this.isPasswordInput()) {
          if (event.key === 'Enter') {
              this.handleSubmit();
          }
          return;
      }

      switch (event.key) {
          case 'Enter':
              event.preventDefault();
              this.handleSubmit();
              break;
          case 'Tab':
              event.preventDefault();
              this.handleTabCompletion();
              break;
          case 'ArrowUp':
              event.preventDefault();
              this.navigateHistory('UP');
              break;
          case 'ArrowDown':
              event.preventDefault();
              this.navigateHistory('DOWN');
              break;
          case 'c':
              if (event.ctrlKey) {
                  event.preventDefault();
                  this.userInput.set(this.userInput() + '^C');
                  this.addMessage('USER', this.userInput() + '^C', 'NEUTRAL');
                  this.userInput.set('');
              }
              break;
          case 'l':
              if (event.ctrlKey) {
                  event.preventDefault();
                  this.messages.set([]);
              }
              break;
      }
  }

  private handleTabCompletion() {
      const rawInput = this.userInput();
      if (!rawInput) return;

      // 1. Command Completion
      if (!rawInput.includes(' ')) {
          const matches = this.supportedCommands.filter(cmd => cmd.startsWith(rawInput));
          if (matches.length === 1) {
              this.userInput.set(matches[0] + ' ');
          } else if (matches.length > 1) {
              const common = this.findCommonPrefix(matches);
              if (common.length > rawInput.length) {
                  this.userInput.set(common);
              } else {
                  this.addMessage('SYSTEM', matches.join('  '), 'NEUTRAL');
              }
          }
          return;
      }

      // 2. Path Completion
      const lastSpace = rawInput.lastIndexOf(' ');
      const prefix = rawInput.substring(0, lastSpace + 1); // "cd "
      const toComplete = rawInput.substring(lastSpace + 1); // "des"

      let searchPath = this.fileService.currentPath();
      let filePrefix = toComplete;
      let dirPrefix = "";

      if (toComplete.includes('/')) {
          const lastSlash = toComplete.lastIndexOf('/');
          dirPrefix = toComplete.substring(0, lastSlash + 1); // "subdir/"
          filePrefix = toComplete.substring(lastSlash + 1);   // "fi"
          
          // Resolve the directory part
          const resolved = this.fileService.resolvePath(dirPrefix);
          if (resolved && resolved.type === 'dir') {
              // Note: listFiles resolves paths, so we can pass dirPrefix if it's relative or absolute
              searchPath = dirPrefix;
          } else {
              return; // Invalid path
          }
      }

      const files = this.fileService.listFiles(searchPath);
      const matches = files.filter(f => f.startsWith(filePrefix));

      if (matches.length === 1) {
          this.userInput.set(prefix + dirPrefix + matches[0]);
      } else if (matches.length > 1) {
          const common = this.findCommonPrefix(matches);
          if (common.length > filePrefix.length) {
              this.userInput.set(prefix + dirPrefix + common);
          } else {
              this.addMessage('SYSTEM', matches.join('  '), 'NEUTRAL');
          }
      }
  }

  private findCommonPrefix(strings: string[]): string {
      if (!strings.length) return '';
      let prefix = strings[0];
      for (let i = 1; i < strings.length; i++) {
          while (strings[i].indexOf(prefix) !== 0) {
              prefix = prefix.substring(0, prefix.length - 1);
              if (prefix === '') return '';
          }
      }
      return prefix;
  }

  private navigateHistory(direction: 'UP' | 'DOWN') {
      const history = this.commandHistory();
      if (history.length === 0) return;

      let idx = this.historyIndex();
      
      if (direction === 'UP') {
          if (idx === -1) {
              idx = history.length - 1;
          } else {
              idx = Math.max(0, idx - 1);
          }
      } else {
          if (idx === -1) return;
          idx = idx + 1;
          if (idx >= history.length) {
              this.historyIndex.set(-1);
              this.userInput.set('');
              return;
          }
      }

      this.historyIndex.set(idx);
      this.userInput.set(history[idx]);
      
      // Defer cursor move
      setTimeout(() => {
          if(this.inputField) {
              this.inputField.nativeElement.selectionStart = this.inputField.nativeElement.selectionEnd = history[idx].length;
          }
      });
  }

  async handleEchoRedirect(args: string) {
      const parts = args.split('>');
      if (parts.length >= 2) {
          let content = parts[0].trim();
          const filename = parts[1].trim();
          
          // Strip quotes
          if ((content.startsWith('"') && content.endsWith('"')) || (content.startsWith("'") && content.endsWith("'"))) {
              content = content.slice(1, -1);
          }
          
          // Handle -e (escapes) - simplified
          content = content.replace(/\\n/g, '\n');

          const err = this.fileService.createFile(filename, content);
          if (err) this.addMessage('SYSTEM', err, 'ERROR');
          else {
              this.addMessage('SYSTEM', `[FS] Written to ${filename}`, 'SUCCESS');
              // Mark as modified if we are in a repo context
              if (this.gitState().initialized) {
                  this.gitState.update(s => ({...s, status: 'MODIFIED'}));
              }
          }
      } else {
           this.addMessage('SYSTEM', 'Echo usage: echo "text" > file.txt', 'ERROR');
      }
  }

  async handleGitCommand(args: string) {
      if (!args) {
          this.addMessage('SYSTEM', 'usage: git <command> [<args>]', 'NEUTRAL');
          return;
      }

      const parts = args.split(' ');
      const op = parts[0];
      const param = parts.slice(1).join(' ');

      if (op === 'init') {
          this.gitState.set({
              initialized: true,
              status: 'CLEAN',
              stagedFiles: [],
              branch: 'main',
              remote: null,
              history: []
          });
          this.addMessage('SYSTEM', `Initialized empty Git repository in ${this.fileService.currentPath()}/.git/`, 'NEUTRAL');
      }
      else if (op === 'clone') {
          if (!param) {
              this.addMessage('SYSTEM', 'fatal: You must specify a repository to clone.', 'ERROR');
              return;
          }
          const repoName = param.split('/').pop()?.replace('.git','') || 'repo';
          await this.addStreamedMessage('AI', `Cloning into '${repoName}'...`, 'NEUTRAL');
          
          await new Promise(r => setTimeout(r, 1000));
          this.addMessage('SYSTEM', `remote: Enumerating objects: 142, done.`);
          await new Promise(r => setTimeout(r, 500));
          this.addMessage('SYSTEM', `remote: Counting objects: 100% (142/142), done.`);
          this.addMessage('SYSTEM', `remote: Compressing objects: 100% (110/110), done.`);
          await new Promise(r => setTimeout(r, 800));
          this.addMessage('SYSTEM', `Receiving objects: 100% (142/142), 1.22 MiB | 4.20 MiB/s, done.`);
          this.addMessage('SYSTEM', `Resolving deltas: 100% (20/20), done.`);
          
          this.fileService.createDirectory(repoName);
          this.fileService.createFile(`${repoName}/README.md`, `# ${repoName}\n\nCloned via Al-Aqrab HaaS.`);
          
          // Set Git State
          this.gitState.set({
              initialized: true,
              status: 'CLEAN',
              stagedFiles: [],
              branch: 'main',
              remote: param,
              history: [{
                  hash: '72b3c1a',
                  msg: 'Initial commit from upstream',
                  author: 'system',
                  date: new Date()
              }]
          });
      }
      else if (op === 'add') {
          if (!this.gitState().initialized) {
              this.addMessage('SYSTEM', 'fatal: not a git repository (or any of the parent directories): .git', 'ERROR');
              return;
          }
          if (!param) {
              this.addMessage('SYSTEM', 'Nothing specified, nothing added.', 'NEUTRAL');
              return;
          }
          // Mock staging
          const files = param === '.' ? ['src/main.ts', 'src/app.component.ts', 'README.md'] : [param];
          this.gitState.update(s => ({
              ...s,
              status: 'STAGED',
              stagedFiles: [...new Set([...s.stagedFiles, ...files])]
          }));
          this.addMessage('SYSTEM', '', 'NEUTRAL'); // Silent on success usually
      }
      else if (op === 'commit') {
          if (!this.gitState().initialized) {
              this.addMessage('SYSTEM', 'fatal: not a git repository', 'ERROR');
              return;
          }
          if (this.gitState().status !== 'STAGED') {
              this.addMessage('SYSTEM', 'On branch main\nnothing to commit, working tree clean', 'NEUTRAL');
              return;
          }
          
          const msgMatch = param.match(/-m\s+["'](.+)["']/);
          const msg = msgMatch ? msgMatch[1] : 'Update';
          const hash = Math.random().toString(16).substring(2, 9);
          
          const newCommit = {
              hash,
              msg,
              author: 'root',
              date: new Date()
          };

          this.gitState.update(s => ({
              ...s,
              status: 'CLEAN',
              stagedFiles: [],
              history: [newCommit, ...s.history]
          }));

          this.addMessage('SYSTEM', `[${this.gitState().branch} ${hash}] ${msg}\n ${Math.floor(Math.random()*5) + 1} files changed, ${Math.floor(Math.random()*100)} insertions(+)`);
          
          // Trigger Post Commit Hook
          await this.handlePostCommitHook();
      }
      else if (op === 'push') {
          if (!this.gitState().initialized) {
              this.addMessage('SYSTEM', 'fatal: not a git repository', 'ERROR');
              return;
          }
          if (!this.gitState().remote) {
              // Check if args has origin
              if (param.includes('origin')) {
                  this.addMessage('SYSTEM', 'fatal: \'origin\' does not appear to be a git repository', 'ERROR');
              } else {
                  this.addMessage('SYSTEM', 'fatal: No configured push destination.\nEither specify the URL from the command-line or configure a remote repository using\n\n    git remote add <name> <url>\n', 'ERROR');
              }
              return;
          }
          
          await this.simulateTypewriterLog([
              'Enumerating objects: 15, done.',
              'Counting objects: 100% (15/15), done.',
              'Delta compression using up to 8 threads',
              'Compressing objects: 100% (12/12), done.',
              'Writing objects: 100% (15/15), 4.12 KiB | 4.12 MiB/s, done.',
              `To ${this.gitState().remote}`,
              `   ${this.gitState().history[1]?.hash || '0000000'}..${this.gitState().history[0].hash}  ${this.gitState().branch} -> ${this.gitState().branch}`
          ]);
      }
      else if (op === 'pull') {
           if (!this.gitState().remote) {
               this.addMessage('SYSTEM', 'fatal: No remote repository specified.', 'ERROR');
               return;
           }
           await this.addStreamedMessage('AI', 'Updating ' + Math.random().toString(16).substring(2,9) + '..' + Math.random().toString(16).substring(2,9), 'NEUTRAL');
           await new Promise(r => setTimeout(r, 1000));
           this.addMessage('SYSTEM', 'Fast-forward\n README.md | 2 +-\n 1 file changed, 1 insertion(+), 1 deletion(-)', 'SUCCESS');
      }
      else if (op === 'status') {
          if (!this.gitState().initialized) {
              this.addMessage('SYSTEM', 'fatal: not a git repository', 'ERROR');
              return;
          }
          const s = this.gitState();
          let out = `On branch ${s.branch}\n`;
          
          if (s.status === 'CLEAN') {
              out += 'nothing to commit, working tree clean';
          } else if (s.status === 'STAGED') {
              out += `Changes to be committed:\n  (use "git restore --staged <file>..." to unstage)\n`;
              s.stagedFiles.forEach(f => out += `\tmodified:   ${f}\n`);
          } else if (s.status === 'MODIFIED') {
              out += `Changes not staged for commit:\n  (use "git add <file>..." to update what will be committed)\n\tmodified:   src/main.ts\n\tmodified:   README.md\n\nno changes added to commit (use "git add" and/or "git commit -a")`;
          }
          this.addMessage('SYSTEM', out, 'NEUTRAL');
      }
      else if (op === 'log') {
          if (!this.gitState().initialized) {
              this.addMessage('SYSTEM', 'fatal: not a git repository', 'ERROR');
              return;
          }
          let out = '';
          this.gitState().history.forEach(commit => {
              out += `commit ${commit.hash}\nAuthor: ${commit.author} <${commit.author}@al-aqrab.local>\nDate:   ${commit.date.toDateString()}\n\n    ${commit.msg}\n\n`;
          });
          this.addMessage('SYSTEM', out.trim(), 'NEUTRAL');
      }
      else if (op === 'remote') {
          if (param.startsWith('add origin')) {
              const url = param.split(' ').pop();
              this.gitState.update(s => ({...s, remote: url || null}));
              this.addMessage('SYSTEM', '', 'NEUTRAL');
          } else if (param === '-v') {
              const r = this.gitState().remote || 'origin';
              this.addMessage('SYSTEM', `origin\t${r} (fetch)\norigin\t${r} (push)`, 'NEUTRAL');
          } else {
              this.addMessage('SYSTEM', '', 'NEUTRAL');
          }
      }
      else if (op === 'checkout') {
           if (param.startsWith('-b')) {
               const branch = param.split(' ')[1];
               this.gitState.update(s => ({...s, branch}));
               this.addMessage('SYSTEM', `Switched to a new branch '${branch}'`, 'NEUTRAL');
           } else {
               this.addMessage('SYSTEM', `Switched to branch '${param}'`, 'NEUTRAL');
           }
      }
      else if (op === 'branch') {
          if (param.startsWith('-M')) {
               const branch = param.split(' ')[1];
               this.gitState.update(s => ({...s, branch}));
               this.addMessage('SYSTEM', '', 'NEUTRAL');
          } else {
              this.addMessage('SYSTEM', `* ${this.gitState().branch}`, 'NEUTRAL');
          }
      }
      else {
          this.addMessage('SYSTEM', `git: '${op}' is not a git command. See 'git --help'.`, 'ERROR');
      }
  }

  async executeCommand(cmd: string, args: string) {
      const lowerCmd = cmd.toLowerCase();
      switch(lowerCmd) {
          case 'help':
              this.addMessage('SYSTEM', `
AL-AQRAB v7.2 (EVOLVED) AVAILABLE COMMANDS:
-------------------------------------------
[SYSTEM]
  help, clear, history, date, whoami, exit, sudo
  build-os --android  (Generate Mobile APK)

[FILESYSTEM]
  ls, cd [dir], pwd, cat [file], mkdir [dir], touch [file], rm [file]
  edit [file] (Nano Editor)

[NETWORK]
  scan [ip]   - Vulnerability Scan (Nmap)
  ssh [host]  - Remote Connection
  tor         - Toggle Tor Proxy
  curl [url]  - Fetch URL

[HACKING TOOLS]
  analyze [threat]  - Threat Intel
  generate [malware]- Create Payload
  audit [file]      - Security Code Audit (Supports uploads)
  
[VERSION CONTROL]
  git init, clone, add, commit, push, pull, status, log, remote

[DEPLOYMENT SCRIPTS]
  deploy_full.sh, deploy_vercel.sh, deploy_railway.sh, deploy_open.sh
  setup_ssl.sh, post-commit-hook.sh

[APPS]
  python3 [script], bash [script]
`, 'NEUTRAL');
              break;
          case 'clear':
              this.messages.set([]);
              break;
          case 'ls':
              const files = this.fileService.listFiles(args || this.fileService.currentPath());
              this.addMessage('SYSTEM', files.length ? files.join('  ') : '(empty directory)', 'NEUTRAL');
              break;
          case 'cd':
              const cdErr = this.fileService.changeDirectory(args);
              if (cdErr) this.addMessage('SYSTEM', cdErr, 'ERROR');
              break;
          case 'pwd':
              this.addMessage('SYSTEM', this.fileService.currentPath(), 'NEUTRAL');
              break;
          case 'cat':
              const node = this.fileService.resolvePath(args);
              if (node && node.type === 'file') {
                  this.addMessage('SYSTEM', node.content || '', 'NEUTRAL');
              } else {
                  this.addMessage('SYSTEM', `cat: ${args}: No such file or directory`, 'ERROR');
              }
              break;
          case 'mkdir':
              const mkErr = this.fileService.createDirectory(args);
              if (mkErr) this.addMessage('SYSTEM', mkErr, 'ERROR');
              else this.addMessage('SYSTEM', `Created directory: ${args}`, 'SUCCESS');
              break;
          case 'touch':
              const tErr = this.fileService.createFile(args, '');
              if (tErr) this.addMessage('SYSTEM', tErr, 'ERROR');
              else this.addMessage('SYSTEM', `Created file: ${args}`, 'SUCCESS');
              break;
          case 'rm':
              const rmErr = this.fileService.removeNode(args);
              if (rmErr) this.addMessage('SYSTEM', rmErr, 'ERROR');
              else this.addMessage('SYSTEM', `Removed: ${args}`, 'SUCCESS');
              break;
          case 'whoami':
              this.addMessage('SYSTEM', 'root', 'NEUTRAL');
              break;
          case 'date':
              this.addMessage('SYSTEM', new Date().toString(), 'NEUTRAL');
              break;
          case 'history':
              this.addMessage('SYSTEM', this.commandHistory().join('\n'), 'NEUTRAL');
              break;
          case 'exit':
              this.addMessage('SYSTEM', 'Logging out...', 'NEUTRAL');
              setTimeout(() => {
                  this.showBios.set(true); // Reset
                  this.messages.set([]);
              }, 1000);
              break;
          case 'tor':
              this.toggleTor();
              break;
          case 'scan':
          case 'nmap':
              if (!args) { this.addMessage('SYSTEM', 'Usage: nmap <target>', 'ERROR'); return; }
              this.addMessage('SYSTEM', `Starting Nmap 7.94 scan against ${args}...`, 'WARNING');
              // Trigger service simulation
              this.geminiService.scanUpdate.next({ target: args, type: 'manual', data: this.scanResults() });
              break;
          case 'ssh':
              if (!args) { this.addMessage('SYSTEM', 'Usage: ssh user@host', 'ERROR'); return; }
              this.addMessage('SYSTEM', `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10, OpenSSL 3.0.2 15 Mar 2022`, 'NEUTRAL');
              this.addMessage('SYSTEM', `debug1: Connecting to ${args} [192.168.1.55] port 22.`, 'NEUTRAL');
              setTimeout(() => {
                  this.addMessage('SYSTEM', `${args}'s password:`, 'WARNING');
                  this.isPasswordInput.set(true);
                  this.pendingProcess.set({ type: 'SSH_AUTH', data: { host: args, key: { name: 'id_rsa', secret: 'toor' } } });
              }, 1000);
              break;
          case 'edit':
          case 'nano':
              if (!args) { this.addMessage('SYSTEM', 'Usage: edit <filename>', 'ERROR'); return; }
              const file = this.fileService.resolvePath(args);
              const initialContent = (file && file.type === 'file') ? (file.content || '') : '';
              
              this.editorContent.set(initialContent);
              this.editorPath.set(args);
              this.isEditorOpen.set(true);
              this.editorStatus.set(`Editing: ${args}`);
              break;
          case 'curl':
              this.addMessage('SYSTEM', `curl: (6) Could not resolve host: ${args}`, 'ERROR');
              break;
          case 'audit':
              // 1. Check for arguments (VFS File)
              if (args) {
                  const f = this.fileService.resolvePath(args);
                  if (f && f.type === 'file') {
                      this.addMessage('SYSTEM', `[AUDIT] Scanning ${args} with Hexstrike SAST...`, 'WARNING');
                      const report = await this.geminiService.auditCode(f.content || '', args);
                      this.addStreamedMessage('AI', report, 'SUCCESS');
                  } else {
                      this.addMessage('SYSTEM', `File not found: ${args}`, 'ERROR');
                  }
                  return;
              }
              
              // 2. Check for Uploaded File
              const attached = this.selectedFile();
              if (attached) {
                   this.addMessage('SYSTEM', `[AUDIT] Decompiling & Scanning uploaded file: ${attached.name}...`, 'WARNING');
                   try {
                       // Safe Base64 decode for UTF-8
                       const binaryString = atob(attached.data);
                       const bytes = new Uint8Array(binaryString.length);
                       for (let i = 0; i < binaryString.length; i++) {
                           bytes[i] = binaryString.charCodeAt(i);
                       }
                       const content = new TextDecoder().decode(bytes);
                       
                       const report = await this.geminiService.auditCode(content, attached.name);
                       this.addStreamedMessage('AI', report, 'SUCCESS');
                       this.selectedFile.set(null); // Clear selection
                   } catch (e) {
                       this.addMessage('SYSTEM', `[ERROR] Failed to decode file: ${e}`, 'ERROR');
                   }
                   return;
              }

              this.addMessage('SYSTEM', 'Usage: audit <filename> OR upload a file and run "audit"', 'ERROR');
              break;
          case 'git':
              await this.handleGitCommand(args);
              break;
          case 'build-os':
              if (args.includes('android') || args === '') {
                  await this.handleSystemBuild();
              } else {
                  this.addMessage('SYSTEM', 'Usage: build-os --android', 'NEUTRAL');
              }
              break;
          case 'dashboard':
          case 'wallet':
              if (args && args.toLowerCase() === 'builder') {
                  this.dashboardTab.set('BUILDER');
              } else if (args && args.toLowerCase() === 'clients') {
                  this.dashboardTab.set('CLIENTS');
              } else {
                  this.dashboardTab.set('OVERVIEW');
              }
              this.openDashboard();
              break;
          default:
              this.addMessage('SYSTEM', `bash: ${cmd}: command not found`, 'ERROR');
      }
  }

  // --- MISSING DEPLOYMENT HANDLERS ---
  
  async handleDeployGithub() {
       await this.addStreamedMessage('AI', '🐙 INITIATING GITHUB DEPLOYMENT...', 'APEX');
       const steps = [
           'git remote add origin https://github.com/root/al-aqrab-haas.git',
           'git branch -M main',
           'git push -u origin main',
           '[+] Branch \'main\' set up to track remote branch \'main\' from \'origin\'.',
           '[+] Deployment triggered via GitHub Actions.'
       ];
       await this.simulateTypewriterLog(steps);
       this.addMessage('SYSTEM', '✅ Repository Live: https://github.com/root/al-aqrab-haas', 'SUCCESS');
  }

  async handlePostCommitHook() {
      this.addMessage('SYSTEM', 'Running .git/hooks/post-commit...', 'NEUTRAL');
      await new Promise(r => setTimeout(r, 600));
      this.addMessage('SYSTEM', '[+] Secret Scanning: CLEAN', 'SUCCESS');
      this.addMessage('SYSTEM', '[+] SAST Check: PASSED', 'SUCCESS');
  }

  async handleDeployVercel() {
      await this.addStreamedMessage('AI', '▲ DEPLOYING TO VERCEL EDGE...', 'APEX');
      await this.simulateTypewriterLog([
          'vercel --prod',
          'Building... [12s]',
          'Output: .vercel/output',
          'Uploading... [Done]',
          'Deployment complete!'
      ]);
      this.addMessage('SYSTEM', '✅ Vercel: https://al-aqrab-haas.vercel.app', 'SUCCESS');
  }

  async handleDeployRailway() {
       await this.addStreamedMessage('AI', '🚂 DEPLOYING TO RAILWAY...', 'APEX');
       await this.simulateTypewriterLog([
           'railway up',
           '[+] Service: al-aqrab-haas',
           '[+] Environment: Production',
           '[+] Building Dockerfile...',
           '[+] Deployment active'
       ]);
       this.addMessage('SYSTEM', '✅ Railway: https://al-aqrab.up.railway.app', 'SUCCESS');
  }

  async handleDeployRender() {
       await this.addStreamedMessage('AI', '☁️ DEPLOYING TO RENDER...', 'APEX');
       await this.simulateTypewriterLog([
           'render deploy',
           'Starting service...',
           'Health check passed.'
       ]);
       this.addMessage('SYSTEM', '✅ Render: https://al-aqrab.onrender.com', 'SUCCESS');
  }

  async handleDeployWebsite() {
      await this.addStreamedMessage('AI', '🌐 DEPLOYING STATIC SITE...', 'APEX');
      await this.simulateTypewriterLog(['npm run build', 'cp -r dist/* /var/www/html/', 'systemctl reload nginx']);
      this.addMessage('SYSTEM', '✅ Website Live: http://localhost', 'SUCCESS');
  }

  async handleMakePublic() {
      await this.simulateTypewriterLog([
          'git config visibility public',
          'git push --force'
      ]);
      this.addMessage('SYSTEM', '✅ Repository is now PUBLIC.', 'SUCCESS');
  }

  async handleSetupVercel() {
      this.addMessage('SYSTEM', 'Vercel CLI v32.0.0', 'NEUTRAL');
      await new Promise(r => setTimeout(r, 800));
      this.addMessage('SYSTEM', 'Linked to root/al-aqrab-haas', 'SUCCESS');
  }

  async handleCertbot() {
      this.addMessage('SYSTEM', 'Running certbot --nginx...', 'NEUTRAL');
      await new Promise(r => setTimeout(r, 1500));
      this.addMessage('SYSTEM', 'Successfully received certificate.', 'SUCCESS');
  }

  // --- NEWLY ADDED HELPER METHODS TO FIX ERRORS ---

  addMessage(role: 'AI' | 'USER' | 'SYSTEM', content: string, status: 'SUCCESS' | 'ERROR' | 'NEUTRAL' | 'WARNING' | 'APEX' = 'NEUTRAL', sources?: {title: string, uri: string}[]) {
      const msg: ChatMessage = {
          id: this.generateId(),
          role,
          content,
          timestamp: new Date(),
          status,
          webSources: sources
      };
      this.messages.update(prev => [...prev, msg]);
      this.saveChatHistory();
      this.shouldScrollToBottom = true;
  }

  async addStreamedMessage(role: 'AI' | 'USER' | 'SYSTEM', content: string, status: 'SUCCESS' | 'ERROR' | 'NEUTRAL' | 'WARNING' | 'APEX' = 'NEUTRAL', sources?: {title: string, uri: string}[]) {
      this.addMessage(role, content, status, sources);
      await new Promise(r => setTimeout(r, Math.min(content.length * 2, 800)));
  }

  async simulateTypewriterLog(lines: string[]) {
      for (const line of lines) {
          this.addMessage('SYSTEM', line, 'NEUTRAL');
          this.audioService.playKeystroke();
          await new Promise(r => setTimeout(r, 200 + Math.random() * 300));
      }
  }

  async handleSystemUpdate() {
      await this.simulateTypewriterLog([
          'CONNECTING TO UPDATE SERVER...',
          'CHECKING REPOSITORIES...',
          'DOWNLOADING PACKAGES...',
          'VERIFYING SIGNATURES... [OK]',
          'INSTALLING UPDATES...',
          'SYSTEM UPDATE COMPLETED.'
      ]);
      this.systemVersion.set('7.3.0 (UPDATED)');
      this.addMessage('SYSTEM', 'System updated to version 7.3.0', 'SUCCESS');
  }

  async handleSystemBuild() {
      await this.addStreamedMessage('AI', 'STARTING BUILD SEQUENCE (ANDROID)...', 'WARNING');
      await this.simulateTypewriterLog([
          'COMPILING SOURCE CODE...',
          'LINKING LIBRARIES...',
          'GENERATING APK...',
          'SIGNING PACKAGE...',
          'BUILD SUCCESSFUL: dist/Al-Aqrab-Mobile.apk'
      ]);
      this.downloadSystemApk();
  }

  async executeShellScript(content: string) {
      const lines = content.split('\n');
      for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) {
               await this.handleSubmitInternal(trimmed);
               await new Promise(r => setTimeout(r, 250));
          }
      }
  }

  async handleCraxsBuilder() {
      await this.simulateTypewriterLog([
          'INITIALIZING CRAXS RAT BUILDER...',
          'INJECTING PAYLOADS...',
          'OBFUSCATING CODE...',
          'SIGNING APK...',
          'BUILD COMPLETE.'
      ]);
      this.ratDownloadLink.set('craxs-rat-v7.4.apk');
      this.downloadRat();
  }

  async handleCraxsC2() {
      await this.addStreamedMessage('SYSTEM', 'STARTING C2 SERVER...', 'WARNING');
      await new Promise(r => setTimeout(r, 1000));
      this.addMessage('SYSTEM', 'LISTENING ON PORT 8080', 'SUCCESS');
      setTimeout(() => {
          this.addMessage('SYSTEM', '[+] NEW CONNECTION: 192.168.1.100 (Android)', 'SUCCESS');
          this.audioService.playAlert('SUCCESS');
      }, 3000);
  }

  async handleDeployBridge() {
      await this.addStreamedMessage('AI', 'DEPLOYING BRIDGE...', 'NEUTRAL');
      await this.simulateTypewriterLog(['CONNECTING...', 'BRIDGE ACTIVE.']);
  }

  async handleDeployFull() {
      await this.addStreamedMessage('AI', 'INITIATING FULL DEPLOY...', 'APEX');
      await this.handleDeployVercel();
      await this.handleDeployRailway();
      await this.handleDeployRender();
      this.addMessage('SYSTEM', 'FULL DEPLOYMENT FINISHED.', 'SUCCESS');
  }

  private generateId(): string {
    return Math.random().toString(36).substring(2, 9) + Date.now().toString(36);
  }

  // --- SECURITY VALIDATOR ---
  private validateInput(text: string): string | null {
      // 1. Buffer Overflow / DoS Protection
      if (text.length > 5000) return 'Buffer Overflow Detected (Max 5000 chars)';
      
      // 2. Prevent HTML/XML Injection (Client-Side Protection)
      // Matches <tag> or </tag> but allows shell redirects like "cat < file" or "echo > file"
      // This regex looks for < followed by a letter or slash, ensuring it's a tag structure.
      const htmlTagPattern = /<[a-zA-Z\/][^>]*>/;
      if (htmlTagPattern.test(text)) return 'HTML/XML Injection Detected';
      
      // 3. Block common XSS vectors
      if (/javascript:/i.test(text) || /vbscript:/i.test(text) || /data:/i.test(text) || /onload=/i.test(text) || /onerror=/i.test(text)) {
          return 'XSS Payload Detected';
      }

      // 4. Block Null Bytes (Memory Corruption Prevention)
      if (text.indexOf('\0') !== -1) return 'Null Byte Injection Detected';

      return null;
  }
}