import argparse
import hashlib
import json
import math
import mimetypes
import os
import platform
import re
import socket
import ssl
import struct
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

try:
    from PIL import Image
except ImportError:
    Image = None


APP_NAME = "TRACEPEEK"
VERSION = "1.0.0"

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"

SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"GIF87a": "GIF Image",
    b"GIF89a": "GIF Image",
    b"%PDF": "PDF Document",
    b"PK\x03\x04": "ZIP Archive / Office Document",
    b"PK\x05\x06": "ZIP Archive",
    b"PK\x07\x08": "ZIP Archive",
    b"Rar!\x1a\x07\x00": "RAR Archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip Archive",
    b"\x1f\x8b": "GZIP Archive",
    b"BM": "BMP Image",
    b"RIFF": "RIFF Container",
    b"ID3": "MP3 Audio",
    b"OggS": "OGG Container",
    b"\x00\x00\x00\x18ftyp": "MP4 Video",
    b"\x00\x00\x00\x20ftyp": "MP4 Video",
    b"MZ": "Windows PE Executable",
}


def enable_colors():
    if os.name == "nt":
        os.system("")


def banner():
    print(f"""
{CYAN}{BOLD}
████████╗██████╗  █████╗  ██████╗███████╗██████╗ ███████╗███████╗██╗  ██╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██║ ██╔╝
   ██║   ██████╔╝███████║██║     █████╗  ██████╔╝█████╗  █████╔╝
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔═══╝ ██╔══╝  ██╔══╝  ██╔═██╗
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██║     ███████╗███████╗██║  ██╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{DIM}Network & File Intelligence Utility • v{VERSION}{RESET}
{DIM}Made by lagback.exe{RESET}
""")


def section(title):
    print(f"\n{CYAN}{BOLD}{title}{RESET}")
    print(f"{DIM}{'─' * 64}{RESET}")


def row(label, value):
    print(f"{WHITE}{label:<20}{RESET}{GREEN}{value}{RESET}")


def error(message):
    print(f"{RED}[ERROR]{RESET} {message}")


def success(message):
    print(f"{GREEN}[+]{RESET} {message}")


def warning(message):
    print(f"{YELLOW}[!]{RESET} {message}")


def format_bytes(size):
    units = ["B", "KB", "MB", "GB", "TB", "PB"]

    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024

    return f"{size:.2f} EB"


def format_time(seconds):
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"

    return f"{seconds:.2f} s"


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url

    return url


def calculate_hash(path, algorithm):
    hasher = hashlib.new(algorithm)

    with open(path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            hasher.update(chunk)

    return hasher.hexdigest()


def detect_signature(path):
    try:
        with open(path, "rb") as file:
            header = file.read(32)

        for signature, name in SIGNATURES.items():
            if header.startswith(signature):
                return name

        return "Unknown"

    except OSError:
        return "Unreadable"


def calculate_entropy(path):
    counts = [0] * 256
    total = 0

    try:
        with open(path, "rb") as file:
            while True:
                chunk = file.read(1024 * 1024)

                if not chunk:
                    break

                total += len(chunk)

                for byte in chunk:
                    counts[byte] += 1

        if total == 0:
            return 0.0

        entropy = 0.0

        for count in counts:
            if count:
                probability = count / total
                entropy -= probability * math.log2(probability)

        return entropy

    except OSError:
        return None


def extract_strings(path, minimum=4, limit=100):
    results = []

    try:
        with open(path, "rb") as file:
            data = file.read()

        current = bytearray()

        for byte in data:
            if 32 <= byte <= 126:
                current.append(byte)
            else:
                if len(current) >= minimum:
                    results.append(current.decode("ascii", errors="ignore"))

                current.clear()

                if len(results) >= limit:
                    break

        if len(current) >= minimum and len(results) < limit:
            results.append(current.decode("ascii", errors="ignore"))

    except OSError:
        pass

    return results


def get_ip_addresses(host):
    ipv4 = set()
    ipv6 = set()

    try:
        results = socket.getaddrinfo(host, None)

        for result in results:
            address = result[4][0]

            if ":" in address:
                ipv6.add(address)
            else:
                ipv4.add(address)

    except socket.gaierror:
        pass

    return sorted(ipv4), sorted(ipv6)


def get_certificate(host, port=443):
    context = ssl.create_default_context()

    with socket.create_connection((host, port), timeout=7) as sock:
        with context.wrap_socket(
            sock,
            server_hostname=host
        ) as secure_sock:

            certificate = secure_sock.getpeercert()

            return {
                "tls_version": secure_sock.version(),
                "cipher": secure_sock.cipher(),
                "certificate": certificate
            }


def command_url(url, json_output=False):
    url = normalize_url(url)
    parsed = urlparse(url)

    if not parsed.hostname:
        error("Invalid URL.")
        return

    start = time.perf_counter()

    result = {
        "target": url,
        "host": parsed.hostname,
        "protocol": parsed.scheme,
        "port": parsed.port or (
            443 if parsed.scheme == "https" else 80
        ),
        "ipv4": [],
        "ipv6": [],
        "http": {},
        "redirects": [],
        "tls": {}
    }

    ipv4, ipv6 = get_ip_addresses(parsed.hostname)

    result["ipv4"] = ipv4
    result["ipv6"] = ipv6

    try:
        response = requests.get(
            url,
            timeout=12,
            allow_redirects=True,
            headers={
                "User-Agent": "TRACEPEEK/2.0"
            }
        )

        result["http"] = {
            "status": response.status_code,
            "reason": response.reason,
            "final_url": response.url,
            "content_type": response.headers.get(
                "Content-Type",
                "Unknown"
            ),
            "server": response.headers.get(
                "Server",
                "Unknown"
            ),
            "content_length": response.headers.get(
                "Content-Length",
                str(len(response.content))
            ),
            "headers": dict(response.headers)
        }

        for redirect in response.history:
            result["redirects"].append({
                "status": redirect.status_code,
                "url": redirect.url
            })

    except requests.RequestException as exc:
        result["error"] = str(exc)

    if parsed.scheme == "https":
        try:
            certificate = get_certificate(
                parsed.hostname,
                parsed.port or 443
            )

            cert = certificate["certificate"]

            result["tls"] = {
                "version": certificate["tls_version"],
                "cipher": certificate["cipher"],
                "subject": str(cert.get("subject", "")),
                "issuer": str(cert.get("issuer", "")),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "serial": cert.get("serialNumber")
            }

        except Exception as exc:
            result["tls"] = {
                "error": str(exc)
            }

    elapsed = time.perf_counter() - start
    result["scan_time"] = elapsed

    if json_output:
        print(json.dumps(result, indent=2, default=str))
        return

    section("TARGET")

    row("URL", url)
    row("Protocol", parsed.scheme.upper())
    row("Host", parsed.hostname)
    row("Port", result["port"])

    section("DNS")

    if ipv4:
        for ip in ipv4:
            row("IPv4", ip)

    if ipv6:
        for ip in ipv6:
            row("IPv6", ip)

    if not ipv4 and not ipv6:
        error("Hostname could not be resolved.")

    if "error" not in result.get("http", {}):
        section("HTTP")

        http = result["http"]

        row(
            "Status",
            f"{http['status']} {http['reason']}"
        )
        row("Final URL", http["final_url"])
        row("Content-Type", http["content_type"])
        row("Server", http["server"])
        row("Size", format_bytes(len(response.content)))

        section("SECURITY HEADERS")

        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        for header in security_headers:
            value = http["headers"].get(header)

            if value:
                print(
                    f"{GREEN}[FOUND]{RESET} "
                    f"{CYAN}{header}{RESET}: {value}"
                )
            else:
                print(
                    f"{DIM}[NONE]{RESET} "
                    f"{header}"
                )

        section("REDIRECTS")

        if result["redirects"]:
            for index, redirect in enumerate(
                result["redirects"],
                1
            ):
                print(
                    f"{CYAN}[{index}]{RESET} "
                    f"{redirect['status']} "
                    f"{redirect['url']}"
                )

            print(
                f"{GREEN}[FINAL]{RESET} "
                f"{response.status_code} "
                f"{response.url}"
            )
        else:
            print(f"{DIM}No redirects detected.{RESET}")

    else:
        error(result["http"]["error"])

    section("TLS")

    if result["tls"] and "error" not in result["tls"]:
        tls = result["tls"]

        row("Version", tls["version"])
        row("Cipher", str(tls["cipher"]))
        row("Issued", tls["not_before"])
        row("Expires", tls["not_after"])
        row("Serial", tls["serial"])

    elif parsed.scheme == "https":
        warning("Could not inspect TLS certificate.")

    else:
        warning("Target is not using HTTPS.")

    print(
        f"\n{DIM}Completed in "
        f"{format_time(elapsed)}{RESET}"
    )


def command_dns(domain):
    domain = domain.replace(
        "https://", ""
    ).replace(
        "http://", ""
    ).split("/")[0]

    section("DNS LOOKUP")

    row("Domain", domain)

    ipv4, ipv6 = get_ip_addresses(domain)

    if ipv4:
        print(f"\n{WHITE}IPv4:{RESET}")

        for address in ipv4:
            print(f"  {GREEN}{address}{RESET}")

    if ipv6:
        print(f"\n{WHITE}IPv6:{RESET}")

        for address in ipv6:
            print(f"  {GREEN}{address}{RESET}")

    if not ipv4 and not ipv6:
        error("No addresses found.")


def command_headers(url):
    url = normalize_url(url)

    section("HTTP HEADERS")

    try:
        response = requests.get(
            url,
            timeout=12,
            allow_redirects=True,
            headers={
                "User-Agent": "TRACEPEEK/2.0"
            }
        )

        row(
            "Status",
            f"{response.status_code} {response.reason}"
        )

        print()

        for key, value in response.headers.items():
            print(
                f"{CYAN}{key:<32}{RESET}"
                f"{value}"
            )

    except requests.RequestException as exc:
        error(str(exc))


def command_redirects(url):
    url = normalize_url(url)

    section("REDIRECT CHAIN")

    try:
        response = requests.get(
            url,
            timeout=12,
            allow_redirects=True,
            headers={
                "User-Agent": "TRACEPEEK/2.0"
            }
        )

        if not response.history:
            success("No redirects detected.")
            print(f"\n{GREEN}{response.url}{RESET}")
            return

        for index, redirect in enumerate(
            response.history,
            1
        ):
            print(
                f"{CYAN}[{index}]{RESET} "
                f"{redirect.status_code} "
                f"{redirect.url}"
            )

        print(
            f"\n{GREEN}[FINAL]{RESET} "
            f"{response.status_code} "
            f"{response.url}"
        )

    except requests.RequestException as exc:
        error(str(exc))


def command_tls(host):
    host = host.replace(
        "https://", ""
    ).replace(
        "http://", ""
    ).split("/")[0]

    section("TLS CERTIFICATE")

    try:
        info = get_certificate(host)

        cert = info["certificate"]

        row("Host", host)
        row("TLS", info["tls_version"])
        row("Cipher", str(info["cipher"]))
        row("Serial", cert.get("serialNumber", "Unknown"))
        row("Valid From", cert.get("notBefore", "Unknown"))
        row("Valid Until", cert.get("notAfter", "Unknown"))

        print(f"\n{WHITE}Subject:{RESET}")

        for group in cert.get("subject", []):
            for key, value in group:
                print(
                    f"  {CYAN}{key}{RESET}: {value}"
                )

        print(f"\n{WHITE}Issuer:{RESET}")

        for group in cert.get("issuer", []):
            for key, value in group:
                print(
                    f"  {CYAN}{key}{RESET}: {value}"
                )

    except Exception as exc:
        error(f"TLS inspection failed: {exc}")


def command_file_info(file_path, full=False):
    path = Path(file_path)

    if not path.exists():
        error("File does not exist.")
        return

    if not path.is_file():
        error("Target is not a file.")
        return

    stat = path.stat()

    signature = detect_signature(path)
    guessed_type = mimetypes.guess_type(path.name)[0]

    section("FILE")

    row("Name", path.name)
    row("Path", str(path.resolve()))
    row("Extension", path.suffix or "None")
    row("Size", format_bytes(stat.st_size))

    section("TYPE")

    row("Signature", signature)
    row("MIME Guess", guessed_type or "Unknown")

    section("TIMESTAMPS")

    row(
        "Created",
        datetime.fromtimestamp(
            stat.st_ctime
        ).strftime("%Y-%m-%d %H:%M:%S")
    )

    row(
        "Modified",
        datetime.fromtimestamp(
            stat.st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S")
    )

    row(
        "Accessed",
        datetime.fromtimestamp(
            stat.st_atime
        ).strftime("%Y-%m-%d %H:%M:%S")
    )

    if full:
        section("HASHES")

        for algorithm in [
            "md5",
            "sha1",
            "sha256",
            "sha512"
        ]:
            try:
                row(
                    algorithm.upper(),
                    calculate_hash(path, algorithm)
                )
            except Exception as exc:
                error(str(exc))

        section("ENTROPY")

        entropy = calculate_entropy(path)

        if entropy is not None:
            row(
                "Shannon Entropy",
                f"{entropy:.4f} / 8.0000"
            )

        if signature == "Windows PE Executable":
            section("PE")

            try:
                with open(path, "rb") as file:
                    file.seek(0x3C)
                    pe_offset = struct.unpack(
                        "<I",
                        file.read(4)
                    )[0]

                    file.seek(pe_offset)
                    signature_bytes = file.read(4)

                    if signature_bytes == b"PE\x00\x00":
                        row("PE Signature", "Valid")

                        machine = struct.unpack(
                            "<H",
                            file.read(2)
                        )[0]

                        machine_names = {
                            0x014C: "x86",
                            0x8664: "x64",
                            0x01C4: "ARM",
                            0xAA64: "ARM64"
                        }

                        row(
                            "Architecture",
                            machine_names.get(
                                machine,
                                hex(machine)
                            )
                        )
                    else:
                        warning(
                            "MZ header found, "
                            "but PE signature was not found."
                        )

            except Exception as exc:
                warning(f"PE inspection failed: {exc}")

    extension = path.suffix.lower()

    if Image and extension in {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp"
    }:
        section("IMAGE")

        try:
            with Image.open(path) as image:
                row("Format", image.format)
                row(
                    "Dimensions",
                    f"{image.width} × {image.height}"
                )
                row("Mode", image.mode)

                if image.info:
                    print(
                        f"\n{WHITE}Embedded Metadata:{RESET}"
                    )

                    for key, value in image.info.items():
                        text = str(value)

                        if len(text) > 200:
                            text = text[:200] + "..."

                        print(
                            f"  {CYAN}{key}{RESET}: "
                            f"{text}"
                        )

        except Exception as exc:
            warning(f"Image inspection failed: {exc}")


def command_meta(file_path):
    command_file_info(file_path, full=True)


def command_hash(file_path):
    path = Path(file_path)

    if not path.exists():
        error("File does not exist.")
        return

    if not path.is_file():
        error("Target is not a file.")
        return

    section("HASH ANALYSIS")

    row("File", path.name)
    row("Size", format_bytes(path.stat().st_size))

    for algorithm in [
        "md5",
        "sha1",
        "sha256",
        "sha512"
    ]:
        start = time.perf_counter()

        try:
            digest = calculate_hash(
                path,
                algorithm
            )

            elapsed = time.perf_counter() - start

            print(
                f"\n{CYAN}{algorithm.upper()}{RESET}"
            )
            print(
                f"{WHITE}{digest}{RESET}"
            )
            print(
                f"{DIM}Calculated in "
                f"{format_time(elapsed)}{RESET}"
            )

        except Exception as exc:
            error(str(exc))


def command_strings(file_path):
    path = Path(file_path)

    if not path.exists():
        error("File does not exist.")
        return

    if not path.is_file():
        error("Target is not a file.")
        return

    section("STRING EXTRACTION")

    strings = extract_strings(path)

    if not strings:
        warning("No printable strings found.")
        return

    row("Found", len(strings))

    print()

    for index, value in enumerate(strings, 1):
        print(
            f"{CYAN}{index:>3}{RESET} "
            f"{value}"
        )


def command_scan(folder):
    path = Path(folder)

    if not path.exists():
        error("Directory does not exist.")
        return

    if not path.is_dir():
        error("Target is not a directory.")
        return

    section("DIRECTORY SCAN")

    files = []
    extensions = Counter()
    total_size = 0

    for item in path.rglob("*"):
        try:
            if item.is_file():
                size = item.stat().st_size

                files.append((item, size))
                total_size += size

                extension = (
                    item.suffix.lower()
                    or "[no extension]"
                )

                extensions[extension] += 1

        except OSError:
            continue

    row("Directory", str(path.resolve()))
    row("Files", len(files))
    row("Total Size", format_bytes(total_size))

    section("FILE TYPES")

    for extension, count in extensions.most_common():
        print(
            f"{CYAN}{extension:<18}{RESET}"
            f"{count}"
        )

    section("FILES")

    for item, size in files:
        try:
            relative = item.relative_to(path)
        except ValueError:
            relative = item

        print(
            f"{CYAN}{relative}{RESET}"
            f" {DIM}({format_bytes(size)}){RESET}"
        )


def command_duplicates(folder):
    path = Path(folder)

    if not path.exists():
        error("Directory does not exist.")
        return

    if not path.is_dir():
        error("Target is not a directory.")
        return

    section("DUPLICATE FINDER")

    hashes = {}
    scanned = 0

    for item in path.rglob("*"):
        if not item.is_file():
            continue

        try:
            digest = calculate_hash(
                item,
                "sha256"
            )

            scanned += 1
            hashes.setdefault(
                digest,
                []
            ).append(item)

        except OSError:
            continue

    duplicates = [
        files
        for files in hashes.values()
        if len(files) > 1
    ]

    row("Files Scanned", scanned)
    row("Duplicate Groups", len(duplicates))

    if not duplicates:
        success("No duplicates found.")
        return

    for index, group in enumerate(
        duplicates,
        1
    ):
        print(
            f"\n{MAGENTA}GROUP {index}{RESET}"
        )

        for file in group:
            print(
                f"  {CYAN}{file}{RESET}"
            )


def command_compare(file_a, file_b):
    a = Path(file_a)
    b = Path(file_b)

    if not a.is_file():
        error(f"File not found: {a}")
        return

    if not b.is_file():
        error(f"File not found: {b}")
        return

    section("FILE COMPARISON")

    row("File A", str(a.resolve()))
    row("File B", str(b.resolve()))

    size_a = a.stat().st_size
    size_b = b.stat().st_size

    row("Size A", format_bytes(size_a))
    row("Size B", format_bytes(size_b))

    hash_a = calculate_hash(a, "sha256")
    hash_b = calculate_hash(b, "sha256")

    section("SHA-256")

    row("A", hash_a)
    row("B", hash_b)

    if hash_a == hash_b:
        print(
            f"\n{GREEN}{BOLD}"
            "FILES ARE IDENTICAL"
            f"{RESET}"
        )
    else:
        print(
            f"\n{YELLOW}{BOLD}"
            "FILES ARE DIFFERENT"
            f"{RESET}"
        )


def command_report(target, output):
    path = Path(output)

    old_stdout = sys.stdout

    try:
        with open(
            path,
            "w",
            encoding="utf-8"
        ) as file:

            class Tee:
                def write(self, data):
                    old_stdout.write(data)
                    file.write(data)

                def flush(self):
                    old_stdout.flush()
                    file.flush()

            sys.stdout = Tee()

            command_inspect(target)

    finally:
        sys.stdout = old_stdout

    success(f"Report saved to {path.resolve()}")


def command_inspect(target):
    if target.startswith(
        ("http://", "https://")
    ):
        command_url(target)
        return

    path = Path(target)

    if path.exists():
        if path.is_file():
            command_meta(target)
        elif path.is_dir():
            command_scan(target)

        return

    if "." in target:
        command_dns(target)
        return

    error(
        "Could not identify target."
    )


def command_version():
    print(f"{APP_NAME} {VERSION}")
    print("Network & File Intelligence Utility")
    print(f"Python {platform.python_version()}")
    print(f"Platform: {platform.platform()}")


def main():
    enable_colors()

    parser = argparse.ArgumentParser(
        prog="tracepeek",
        description=(
            "TRACEPEEK - Network & File "
            "Intelligence Utility"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Hide the TRACEPEEK banner"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON where supported"
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    p = subparsers.add_parser(
        "url",
        help="Inspect a URL"
    )
    p.add_argument("target")

    p = subparsers.add_parser(
        "dns",
        help="Resolve IPv4 and IPv6 addresses"
    )
    p.add_argument("domain")

    p = subparsers.add_parser(
        "headers",
        help="Inspect HTTP response headers"
    )
    p.add_argument("url")

    p = subparsers.add_parser(
        "redirects",
        help="Show the complete redirect chain"
    )
    p.add_argument("url")

    p = subparsers.add_parser(
        "tls",
        help="Inspect TLS certificate information"
    )
    p.add_argument("host")

    p = subparsers.add_parser(
        "info",
        help="Basic file information"
    )
    p.add_argument("file")

    p = subparsers.add_parser(
        "meta",
        help="Deep file metadata inspection"
    )
    p.add_argument("file")

    p = subparsers.add_parser(
        "hash",
        help="Calculate multiple cryptographic hashes"
    )
    p.add_argument("file")

    p = subparsers.add_parser(
        "strings",
        help="Extract printable strings"
    )
    p.add_argument("file")

    p = subparsers.add_parser(
        "scan",
        help="Recursively scan a directory"
    )
    p.add_argument("folder")

    p = subparsers.add_parser(
        "duplicates",
        help="Find duplicate files"
    )
    p.add_argument("folder")

    p = subparsers.add_parser(
        "compare",
        help="Compare two files using SHA-256"
    )
    p.add_argument("file_a")
    p.add_argument("file_b")

    p = subparsers.add_parser(
        "inspect",
        help="Automatically inspect a target"
    )
    p.add_argument("target")

    p = subparsers.add_parser(
        "report",
        help="Inspect target and save terminal output"
    )
    p.add_argument("target")
    p.add_argument("output")

    subparsers.add_parser(
        "version",
        help="Show version information"
    )

    args = parser.parse_args()

    if not args.no_banner:
        banner()

    if not args.command:
        parser.print_help()
        return

    if args.command == "url":
        command_url(args.target, args.json)

    elif args.command == "dns":
        command_dns(args.domain)

    elif args.command == "headers":
        command_headers(args.url)

    elif args.command == "redirects":
        command_redirects(args.url)

    elif args.command == "tls":
        command_tls(args.host)

    elif args.command == "info":
        command_file_info(args.file)

    elif args.command == "meta":
        command_meta(args.file)

    elif args.command == "hash":
        command_hash(args.file)

    elif args.command == "strings":
        command_strings(args.file)

    elif args.command == "scan":
        command_scan(args.folder)

    elif args.command == "duplicates":
        command_duplicates(args.folder)

    elif args.command == "compare":
        command_compare(
            args.file_a,
            args.file_b
        )

    elif args.command == "inspect":
        command_inspect(args.target)

    elif args.command == "report":
        command_report(
            args.target,
            args.output
        )

    elif args.command == "version":
        command_version()


if __name__ == "__main__":
    main()