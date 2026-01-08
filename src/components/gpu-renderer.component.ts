import { Component, ElementRef, ViewChild, Input, OnDestroy, AfterViewInit, NgZone, effect, signal } from '@angular/core';

@Component({
  selector: 'app-gpu-renderer',
  template: '<canvas #glCanvas class="absolute inset-0 w-full h-full pointer-events-none opacity-60 mix-blend-screen z-0"></canvas>',
  styles: []
})
export class GpuRendererComponent implements AfterViewInit, OnDestroy {
  @ViewChild('glCanvas') canvasRef!: ElementRef<HTMLCanvasElement>;
  
  viewMode = signal<string>('TERMINAL');
  @Input() set mode(val: string) { this.viewMode.set(val); }

  private gl!: WebGL2RenderingContext;
  private program!: WebGLProgram;
  private animationId: number = 0;
  private startTime: number = 0;

  // Vertex Shader (Full screen quad)
  private readonly vsSource = `#version 300 es
    in vec4 position;
    void main() {
      gl_Position = position;
    }
  `;

  // Fragment Shader (The visual logic)
  private readonly fsSource = `#version 300 es
    precision highp float;
    
    uniform vec2 u_resolution;
    uniform float u_time;
    uniform float u_mode; // 0.0 = TERMINAL, 1.0 = DASHBOARD
    
    out vec4 outColor;

    // Pseudo-random function
    float random(vec2 st) {
        return fract(sin(dot(st.xy, vec2(12.9898,78.233))) * 43758.5453123);
    }

    // Value Noise
    float noise(vec2 st) {
        vec2 i = floor(st);
        vec2 f = fract(st);
        float a = random(i);
        float b = random(i + vec2(1.0, 0.0));
        float c = random(i + vec2(0.0, 1.0));
        float d = random(i + vec2(1.0, 1.0));
        vec2 u = f * f * (3.0 - 2.0 * f);
        return mix(a, b, u.x) + (c - a)* u.y * (1.0 - u.x) + (d - b) * u.x * u.y;
    }

    // --- EFFECT 1: DIGITAL RAIN (TERMINAL) ---
    vec3 digitalRain(vec2 uv) {
        vec2 grid = vec2(50.0, 20.0); // Columns, Rows density
        vec2 ipos = floor(uv * grid);
        vec2 fpos = fract(uv * grid);
        
        // Falling speed varies by column
        float speed = 2.0 + random(vec2(ipos.x, 0.0)) * 3.0;
        float yOffset = u_time * speed;
        
        // Random character flickering
        float charVal = random(ipos + vec2(0.0, floor(yOffset)));
        float flicker = step(0.95, sin(u_time * 10.0 + random(ipos)*10.0));
        
        // Trail effect
        float trail = fract((ipos.y / grid.y) + yOffset * 0.1);
        trail = pow(trail, 4.0); // Fade out tail
        
        // Matrix Green/Red shift (Soviet Red)
        vec3 color = vec3(0.8, 0.0, 0.0) * trail;
        
        // Bright head of the stream
        if (trail > 0.95) color = vec3(1.0, 0.8, 0.8);
        
        // Random glitched characters
        if (charVal > 0.5) color *= 0.5;
        
        return color * (0.2 + 0.8 * random(ipos + vec2(u_time)));
    }

    // --- EFFECT 2: THREAT GRID (DASHBOARD) ---
    vec3 threatGrid(vec2 uv) {
        // Center UV
        vec2 st = uv * 2.0 - 1.0;
        st.x *= u_resolution.x / u_resolution.y;
        
        // Rotation
        float t = u_time * 0.1;
        mat2 rot = mat2(cos(t), -sin(t), sin(t), cos(t));
        vec2 rotSt = st * rot;
        
        // Perspective warp (Fake 3D plane)
        float z = 1.0 + (rotSt.y + 0.5) * 0.5;
        vec2 gridUV = rotSt / z;
        
        // Grid lines
        gridUV *= 10.0; // Grid density
        gridUV.y -= u_time * 2.0; // Movement
        
        vec2 gridFract = fract(gridUV);
        float lines = step(0.95, gridFract.x) + step(0.95, gridFract.y);
        
        // Radar sweep
        float angle = atan(st.y, st.x);
        float sweep = smoothstep(0.0, 0.1, abs(mod(angle + u_time * 2.0, 3.14159 * 2.0) - 3.14159));
        
        // Nodes (Bots)
        float nodes = 0.0;
        vec2 id = floor(gridUV);
        if (random(id) > 0.96) {
            float pulse = 0.5 + 0.5 * sin(u_time * 5.0 + random(id) * 10.0);
            nodes = pulse * step(length(gridFract - 0.5), 0.3);
        }
        
        vec3 color = vec3(0.6, 0.0, 0.0) * lines * 0.3; // Dark red grid
        color += vec3(1.0, 0.2, 0.0) * nodes; // Bright orange/red nodes
        color += vec3(0.5, 0.0, 0.0) * sweep * 0.2; // Radar ambient
        
        // Vignette
        color *= 1.0 - length(st) * 0.5;
        
        return color;
    }

    void main() {
        vec2 uv = gl_FragCoord.xy / u_resolution.xy;
        vec3 color = vec3(0.0);
        
        // Smooth transition logic could go here, but strict switching is fine for this OS feel
        if (u_mode < 0.5) {
            color = digitalRain(uv);
        } else {
            color = threatGrid(uv);
        }
        
        // Scanlines (Global)
        float scanline = sin(uv.y * u_resolution.y * 0.5);
        color *= 0.8 + 0.2 * scanline;
        
        outColor = vec4(color, 1.0); // Alpha handled by CSS opacity
    }
  `;

  constructor(private ngZone: NgZone) {}

  ngAfterViewInit() {
    this.initWebGL();
    this.startTime = performance.now();
    // Run outside Angular to prevent ChangeDetection spam on every frame
    this.ngZone.runOutsideAngular(() => this.renderLoop());
  }

  ngOnDestroy() {
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
    }
    // Cleanup GL
    if (this.gl && this.program) {
        this.gl.deleteProgram(this.program);
    }
  }

  private initWebGL() {
    const canvas = this.canvasRef.nativeElement;
    // Handle DPI scaling
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.clientWidth * dpr;
    canvas.height = canvas.clientHeight * dpr;
    
    const gl = canvas.getContext('webgl2');
    if (!gl) {
      console.warn('WebGL2 not supported, falling back to CSS effects.');
      return;
    }
    this.gl = gl;

    // Compile Shaders
    const vs = this.createShader(gl, gl.VERTEX_SHADER, this.vsSource);
    const fs = this.createShader(gl, gl.FRAGMENT_SHADER, this.fsSource);
    if (!vs || !fs) return;

    // Link Program
    const program = gl.createProgram();
    if (!program) return;
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);

    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      console.error(gl.getProgramInfoLog(program));
      return;
    }
    this.program = program;

    // Set up geometry (Full screen quad)
    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    const positions = [
      -1.0, -1.0,
       1.0, -1.0,
      -1.0,  1.0,
      -1.0,  1.0,
       1.0, -1.0,
       1.0,  1.0,
    ];
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(positions), gl.STATIC_DRAW);

    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    const positionAttributeLocation = gl.getAttribLocation(program, "position");
    gl.enableVertexAttribArray(positionAttributeLocation);
    gl.vertexAttribPointer(positionAttributeLocation, 2, gl.FLOAT, false, 0, 0);
  }

  private createShader(gl: WebGL2RenderingContext, type: number, source: string): WebGLShader | null {
    const shader = gl.createShader(type);
    if (!shader) return null;
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      console.error(gl.getShaderInfoLog(shader));
      gl.deleteShader(shader);
      return null;
    }
    return shader;
  }

  private renderLoop() {
    if (!this.gl || !this.program) return;

    const render = () => {
      // Resize handling
      const canvas = this.canvasRef.nativeElement;
      const dpr = window.devicePixelRatio || 1;
      const displayWidth = Math.floor(canvas.clientWidth * dpr);
      const displayHeight = Math.floor(canvas.clientHeight * dpr);

      if (canvas.width !== displayWidth || canvas.height !== displayHeight) {
        canvas.width = displayWidth;
        canvas.height = displayHeight;
        this.gl.viewport(0, 0, canvas.width, canvas.height);
      }

      this.gl.useProgram(this.program);

      // Uniforms
      const uRes = this.gl.getUniformLocation(this.program, "u_resolution");
      const uTime = this.gl.getUniformLocation(this.program, "u_time");
      const uMode = this.gl.getUniformLocation(this.program, "u_mode");

      this.gl.uniform2f(uRes, canvas.width, canvas.height);
      this.gl.uniform1f(uTime, (performance.now() - this.startTime) / 1000);
      
      // Determine mode float
      const modeFloat = this.viewMode() === 'DASHBOARD' ? 1.0 : 0.0;
      this.gl.uniform1f(uMode, modeFloat);

      // Draw
      this.gl.drawArrays(this.gl.TRIANGLES, 0, 6);

      this.animationId = requestAnimationFrame(render);
    };
    render();
  }
}
