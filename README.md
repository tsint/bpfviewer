# bpfviewer - eBPF Disassembler & Visualizer

A developer tool for disassembling, analyzing, debugging, and visualizing BPF object files.

[中文文档](README_zh.md)

## Background & Motivation

eBPF development can be challenging, especially when dealing with BPF program load errors. While the kernel provides verbose error messages through `bpftool prog dump xlated` and the verifier log, mapping these errors back to the original source code is often difficult and time-consuming.

Existing tools like `llvm-objdump` provide basic disassembly, but they lack:
- Visual representation of program-to-map relationships
- Easy-to-read instruction formatting
- Quick navigation between programs and their associated data structures
- Web-based interactive viewing

**bpfviewer** was created to fill this gap. It provides a comprehensive view of your compiled BPF object files, making it easier to:
- Debug BPF loading failures
- Understand the compiled output
- Visualize how programs interact with maps
- Bridge the gap between kernel verifier output and your source code

We hope this tool will make eBPF development more productive and less frustrating.

## Features

### Disassembly
- Full BPF instruction disassembly from ELF object files
- Human-readable instruction formatting with register names
- **Source-to-instruction mapping** — displays BPF instructions alongside corresponding source code for easier debugging and understanding of compiler optimizations
- Program metadata including section, type, and instruction offset
- Support for all standard BPF instruction types
- **Note**: BPF programs must be compiled with the `-g` option to preserve debug information

### Visualization
- **Mermaid flow graphs** showing program-to-map relationships
- Automatic detection of map operations (Lookup, Update, Delete)
- Interactive HTML output with syntax highlighting
- Side-by-side view of disassembly code and relationship graphs

### Dual Mode Operation
- **CLI mode**: Generate a standalone HTML file from a BPF object
- **Daemon mode**: HTTP server with web UI for uploading and viewing multiple files

## Installation

```bash
go build -o bpfviewer main.go ins.go
```

## Usage

### CLI Mode

Generate an HTML file from a BPF object file:

```bash
./bpfviewer -f <bpf-file>
```

Options:
- `-f, --file`: BPF object file to parse (required)
- `-t, --temp`: HTML template file (default: `bpf_template.html`)
- `--host`: Home page URL for the back button
- `--version`: Show version and exit

Example:
```bash
./bpfviewer -f tracer.o
# Output: tracer.html
```

### Daemon Mode

Run as an HTTP server with web UI:

```bash
./bpfviewer --daemon [--listen :8086]
```

Options:
- `--daemon`: Run in daemon mode (HTTP server)
- `--listen`: Listen address (default: `:8086`)

The server provides:
- File upload via drag-and-drop web UI
- Automatic HTML generation on demand
- File management (list, view, delete)
- Pre-generated HTML file serving

Open `http://localhost:8086` in your browser to access the web interface.

## Output Example

The generated HTML includes:

1. **Source Section**: Disassembled BPF instructions
![code](images/code.png)

2. **Graph Section**: Visual relationship diagram
![relationship](images/relationship.png)

## Project Structure

```
bpfviewer/
├── main.go           # Main program logic, HTTP handlers
├── ins.go            # BPF instruction disassembly & formatting
├── bpf_template.html # Template for generated HTML visualization
├── home.html         # Home page for daemon mode
├── bpf/              # Directory for uploaded BPF object files
└── html/             # Directory for generated HTML files
```

## Dependencies

- [cilium/ebpf](https://github.com/cilium/ebpf) - eBPF library for Go
- [logrus](https://github.com/sirupsen/logrus) - Structured logger
- [pflag](https://github.com/spf13/pflag) - POSIX-compliant command-line flags

## Comparison with Other Tools

| Tool | Disassembly | Visualization | Web UI | Prog-Map Relationships |
|------|-------------|---------------|--------|-------------------|
| **bpfviewer** | ✅ | ✅ | ✅ | ✅ |
| llvm-objdump | ✅ | ❌ | ❌ | ❌ |
| bpftool | ✅ | ❌ | ❌ | Limited |

## License

Licensed under the Apache License, Version 2.0 or the Mulan Permissive 
Software License, Version 2 (Mulan PSL v2). You may choose either license 
to govern your use of this software.

1. Apache License 2.0: https://www.apache.org/licenses/LICENSE-2.0 
2. Mulan PSL v2: https://license.coscl.org.cn/MulanPSL2

Unless required by applicable law or agreed to in writing, software 
distributed under either license is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
