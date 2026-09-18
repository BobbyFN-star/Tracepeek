# tracepeek
<img width="1370" height="673" alt="image" src="https://github.com/user-attachments/assets/d7e47797-1218-41fd-9deb-784f6f5ea900" />

# TRACEPEEK

TRACEPEEK is a Python command-line tool for inspecting URLs, domains, files, and directories.

It combines network and file analysis into one simple utility. You can use it to check DNS records, HTTP headers, redirects, TLS information, file metadata, hashes, file signatures, entropy, strings, duplicates, and more.

## Features

* URL and HTTP inspection
* DNS lookup
* TLS certificate information
* HTTP headers and redirects
* File metadata
* File signature detection
* MD5, SHA-1, SHA-256 and SHA-512 hashes
* Entropy analysis
* Printable string extraction
* Directory scanning
* Duplicate file detection
* File comparison
* Report generation
* JSON output
* Automatic target detection

## Setup

### 1. Install Python

Download and install Python 3.10 or newer.

Make sure to enable **Add Python to PATH** during installation.

### 2. Download TRACEPEEK

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/TRACEPEEK.git
cd TRACEPEEK
```

Or download the repository as a ZIP and extract it.

### 3. Install dependencies

```bash
pip install requests pillow
```

Pillow is optional and is mainly used for additional image information.

### 4. Run TRACEPEEK

```bash
python tracepeek.py --help
```

You can then start using commands such as:

```bash
python tracepeek.py inspect example.com
```

```bash
python tracepeek.py info "file.exe"
```

```bash
python tracepeek.py scan "C:\Downloads"
```

## Requirements

* Windows, Linux, or macOS
* Python 3.10+
* requests
* Pillow (optional)

TRACEPEEK is made for developers, security learners, and anyone who wants a quick way to inspect network and file information from the terminal.

Made by lagback.exe
