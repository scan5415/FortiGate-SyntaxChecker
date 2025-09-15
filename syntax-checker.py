import argparse
import ipaddress
import shlex
from pathlib import Path
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.highlighter import ReprHighlighter
from rich.progress import Progress

#!/usr/bin/env python3
"""
forticli_check.py

Simple FortiGate CLI syntax heuristic checker.

- Reads an input text file (CLI script)
- Applies a set of heuristic checks inspired by FortiGate CLI logic
    (config/edit/set/next/end structure, common mistakes, unmatched quotes,
     basic IP validation, use of '=' instead of space, missing arguments, etc.)
- Prints a human-friendly table of potential issues using rich

Note: This is a heuristic linter, not an authoritative parser of FortiGate CLI.
It is intentionally conservative and flags likely problems, not a definitive
validation against the official CLI reference.

Usage:
        python forticli_check.py path/to/cli_script.txt
"""



# Minimal set of known top-level commands for heuristic checking
KNOWN_TOP_LEVEL = {
        "config",
        "end",
        "edit",
        "next",
        "set",
        "unset",
        "get",
        "show",
        "execute",
        "diagnose",
        "append",
        "delete",
        "rename",
        "move",
        "exit",
        "save",
        "load",
        "backup",
        "restore",
        "patch",
        "switch",
        "add",
        "clear",
}

BOOLEAN_VALUES = {"enable", "disable", "true", "false", "1", "0", "on", "off"}


def is_ipv4(address: str) -> bool:
        try:
                ipaddress.IPv4Address(address)
                return True
        except Exception:
                return False


def parse_line(line: str):
        """
        Return (tokens, parse_error)
        tokens: list of tokens (naive split preserving quotes via shlex)
        parse_error: string if parsing failed (e.g. unmatched quotes)
        """
        # Remove inline comment starting with '#' except when inside quotes:
        # Use a quick heuristic: if no quotes, strip at first '#'
        if '"' not in line and "'" not in line:
                if "#" in line:
                        line = line.split("#", 1)[0]
        try:
                tokens = shlex.split(line, posix=True)
                return tokens, None
        except ValueError as e:
                # shlex reports unmatched quotes, etc.
                return [], str(e)


def analyze_file(path: Path) -> List[Dict]:
    issues = []
    stack = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    n = len(lines)
    i = 0
    in_set_buffer_block = False

    console = Console()
    with Progress(transient=True, console=console) as progress:
        task = progress.add_task("[cyan]Analyzing lines...", total=n)
        while i < n:
            raw = lines[i]
            line = raw.rstrip("\n")
            stripped = line.strip()
            progress.update(task, advance=1, description=f"[cyan]Analyzing line {i+1}/{n}")

            if stripped == "":
                i += 1
                continue

            # Skip full-line comments first!
            if stripped.startswith("#") or stripped.startswith("//"):
                i += 1
                continue

            # If inside a set buffer multiline block, skip lines until closing quote
            if in_set_buffer_block:
                # Check if this line ends the block
                if '"' in line and not line.rstrip().endswith('\\"'):
                    in_set_buffer_block = False
                i += 1
                continue

            # Detect quoted multiline value (starts with set ... "<something)
            if (
                stripped.lower().startswith("set ")
                and '"' in stripped
                and stripped.count('"') >= 1
                and not stripped.endswith('"')
            ):
                cmd_part = line[: line.index('"')]
                value_lines = [line[line.index('"') + 1 :]]
                start_line = i + 1
                i += 1
                is_set_buffer = cmd_part.strip().lower().startswith("set buffer")
                while i < n:
                    next_line = lines[i]
                    value_lines.append(next_line)
                    if '"' in next_line and not '\\"' in next_line:
                        # If this is a set buffer block, skip the closing quote line as well
                        if is_set_buffer:
                            i += 1
                            in_set_buffer_block = False
                            break
                        else:
                            break
                    i += 1
                full_value = "\n".join(value_lines)
                if full_value.endswith('"'):
                    full_value = full_value[:-1]
                full_cmd = f"{cmd_part}\"{full_value}\""
                if is_set_buffer:
                    # Enter set buffer block, skip all lines until closing quote
                    in_set_buffer_block = False  # Already handled above
                    continue
                # Now analyze as a single command/value (for other multiline quoted commands)
                tokens, parse_err = parse_line(full_cmd)
                if parse_err:
                    issues.append(
                        {
                            "line": start_line,
                            "text": full_cmd,
                            "severity": "ERROR",
                            "issue": "Parse error",
                            "details": f"Parsing failed: {parse_err}",
                        }
                    )
                    i += 1
                    continue

                cmd = tokens[0].lower() if tokens else ""
                # Multiline command context check
                multiline_cmds = ["set certificate", "set key"]
                for mcmd in multiline_cmds:
                    if full_cmd.lower().startswith(mcmd):
                        valid_contexts = {
                            "set certificate": ["config vpn certificate local", "config firewall ssh local-key"],
                            "set key": ["config firewall ssh local-key", "config vpn certificate local"],
                        }
                        current_context = None
                        for s in reversed(stack):
                            if s[0] == "config":
                                current_context = s[1].lower()
                                break
                        expected = valid_contexts[mcmd]
                        if not current_context or all(ec not in current_context for ec in expected):
                            issues.append(
                                {
                                    "line": start_line,
                                    "text": full_cmd,
                                    "severity": "ERROR",
                                    "issue": f"Misplaced multiline command '{mcmd}'",
                                    "details": f"'{mcmd}' should be inside one of: {expected}. Found in: '{current_context or 'no config block'}'.",
                            }
                            )
                # Certificate block validation
                if full_cmd.lower().startswith("set certificate"):
                    cert_text = full_value
                    has_pub = "-----BEGIN CERTIFICATE-----" in cert_text and "-----END CERTIFICATE-----" in cert_text
                    has_priv = "-----BEGIN ENCRYPTED PRIVATE KEY-----" in cert_text and "-----END ENCRYPTED PRIVATE KEY-----" in cert_text
                    if not has_pub:
                        issues.append(
                            {
                                "line": start_line,
                                "text": full_cmd,
                                "severity": "ERROR",
                                "issue": "Certificate missing public key",
                                "details": "Certificate block must contain a public key (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----).",
                            }
                        )
                    if has_priv and not has_pub:
                        issues.append(
                            {
                                "line": start_line,
                                "text": full_cmd,
                                "severity": "ERROR",
                                "issue": "Private key without public key",
                                "details": "Certificate block contains a private key but no public key.",
                            }
                        )
                i += 1
                continue

            # Only check for \" usage outside set buffer blocks
            if '\\"' in line:
                issues.append(
                    {
                        "line": i + 1,
                        "text": line,
                        "severity": "ERROR",
                        "issue": "Invalid escape sequence",
                        "details": "Use of \\\" is only allowed in comments in FortiGate configs.",
                    }
                )

            tokens, parse_err = parse_line(line)
            if parse_err:
                issues.append(
                    {
                        "line": i + 1,
                        "text": line,
                        "severity": "ERROR",
                        "issue": "Parse error",
                        "details": f"Parsing failed: {parse_err}",
                    }
                )
                i += 1
                continue

            if not tokens:
                i += 1
                continue

            cmd = tokens[0].lower()

            # Unknown top-level command
            if cmd not in KNOWN_TOP_LEVEL:
                issues.append(
                    {
                        "line": i + 1,
                        "text": line,
                        "severity": "WARNING",
                        "issue": "Unknown or uncommon command",
                        "details": f"Top token '{tokens[0]}' not in known CLI tokens set.",
                    }
                )

            # Specific command heuristics
            if cmd == "config":
                if len(tokens) < 2:
                    issues.append(
                        {
                            "line": i + 1,
                            "text": line,
                            "severity": "ERROR",
                            "issue": "Missing config section",
                            "details": "Usage: config <section> (e.g. config system interface)",
                        }
                    )
                else:
                    section = " ".join(tokens[1:])
                    stack.append(("config", section))

            elif cmd == "edit":
                if len(tokens) < 2:
                    issues.append(
                        {
                            "line": i + 1,
                            "text": line,
                            "severity": "ERROR",
                            "issue": "Missing edit argument",
                            "details": "Usage: edit <name_or_index>",
                        }
                    )
                    stack.append(("edit", None))
                else:
                    stack.append(("edit", tokens[1]))

            elif cmd == "next":
                if not stack:
                    issues.append(
                        {
                            "line": i + 1,
                            "text": line,
                            "severity": "ERROR",
                            "issue": "Unexpected 'next'",
                            "details": "'next' without a matching 'edit' block above.",
                        }
                    )
                else:
                    top = stack[-1]
                    if top[0] == "edit":
                        stack.pop()
                    else:
                        issues.append(
                            {
                                "line": i + 1,
                                "text": line,
                                "severity": "ERROR",
                                "issue": "Misplaced 'next'",
                                "details": "'next' found, but the most recent open block isn't an 'edit'.",
                            }
                        )
                if len(tokens) > 1:
                    issues.append(
                        {
                            "line": i + 1,
                            "text": line,
                            "severity": "INFO",
                            "issue": "Extra tokens after 'next'",
                            "details": "Typical usage is a single 'next' line. Extra tokens ignored.",
                        }
                    )

            elif cmd == "end":
                if not stack:
                    issues.append(
                        {
                            "line": i + 1,
                            "text": line,
                            "severity": "ERROR",
                            "issue": "Unexpected 'end'",
                            "details": "'end' without a matching 'config' block above.",
                        }
                    )
                else:
                    found = False
                    for j in range(len(stack) - 1, -1, -1):
                        if stack[j][0] == "config":
                            found = True
                            for _ in range(len(stack) - j):
                                stack.pop()
                            break
                    if not found:
                        issues.append(
                            {
                                "line": i + 1,
                                "text": line,
                                "severity": "ERROR",
                                "issue": "Misplaced 'end'",
                                "details": "'end' found, but no open 'config' block.",
                            }
                        )
                if len(tokens) > 1:
                    issues.append(
                        {
                            "line": i + 1,
                            "text": line,
                            "severity": "INFO",
                            "issue": "Extra tokens after 'end'",
                            "details": "Typical usage is a single 'end' line. Extra tokens ignored.",
                        }
                    )

            elif cmd == "set":
                if len(tokens) < 2:
                    issues.append(
                        {
                            "line": i + 1,
                            "text": line,
                            "severity": "ERROR",
                            "issue": "Incomplete 'set'",
                            "details": "Usage: set <option> [value]. Option missing.",
                        }
                    )
                else:
                    if "=" in line and not any(excl in line for excl in ("buffer", "ENC", "str", "query", "public-key", "pattern", '\"=\"')):
                        issues.append(
                            {
                                "line": i + 1,
                                "text": line,
                                "severity": "WARNING",
                                "issue": "Assignment using '='",
                                "details": "FortiGate CLI uses space-separated tokens: 'set option value', not 'option=value'.",
                            }
                        )
                    if len(tokens) == 2:
                        opt = tokens[1].lower()
                        if opt not in BOOLEAN_VALUES:
                            issues.append(
                                {
                                    "line": i + 1,
                                    "text": line,
                                    "severity": "WARNING",
                                    "issue": "Missing value for 'set'",
                                    "details": "Only an option provided; many 'set' commands require an explicit value.",
                                }
                            )
                    else:
                        last = tokens[-1]
                        if is_ipv4(last) is False and any(tok.lower() in ("ip", "gateway", "remote-ip", "remote") for tok in tokens[1:3]):
                            if last.lower() not in ("ip", "disable", "remote"):
                                issues.append(
                                    {
                                        "line": i + 1,
                                        "text": line,
                                        "severity": "ERROR",
                                        "issue": "Invalid IP address",
                                        "details": f"Value '{last}' doesn't appear to be a valid IPv4 address.",
                                    }
                                )
                        
                        if is_ipv4(last):
                            if "/" in last:
                                try:
                                    ipaddress.IPv4Network(last, strict=False)
                                except Exception:
                                    issues.append(
                                        {
                                            "line": i + 1,
                                            "text": line,
                                            "severity": "ERROR",
                                            "issue": "Invalid network",
                                            "details": f"'{last}' is not a valid IPv4 network.",
                                        }
                                    )

            if cmd in ("get", "show", "diagnose", "execute") and len(tokens) == 1:
                issues.append(
                    {
                        "line": i + 1,
                        "text": line,
                        "severity": "INFO",
                        "issue": f"Possibly incomplete '{cmd}'",
                        "details": f"'{cmd}' usually takes subcommands or arguments; verify this is intentional.",
                    }
                )

            i += 1

    # After file processed, check for any unclosed blocks
    if stack:
        for kind, name in stack:
            issues.append(
                {
                    "line": None,
                    "text": "",
                    "severity": "ERROR",
                    "issue": f"Unclosed block: {kind}",
                    "details": f"Block started for '{kind}'{' '+str(name) if name else ''} was not closed (missing 'next'/'end').",
                }
            )

    return issues


def print_issues_table(issues: List[Dict], include_warnings: bool = False):
    console = Console()
    table = Table(title="CLI Syntax Check Results", show_lines=False)
    table.add_column("Line", justify="right", style="cyan", no_wrap=True)
    table.add_column("Severity", style="magenta")
    table.add_column("Issue", style="red")
    table.add_column("Details", style="white")

    for it in issues:
        if not include_warnings and it.get("severity") == "WARNING":
            continue
        if it.get("issue") == "Invalid escape sequence":
            continue  # Ignore all "Invalid escape sequence" issues
        line = str(it["line"]) if it["line"] is not None else "-"
        severity = it.get("severity", "")
        issue = it.get("issue", "")
        details = it.get("details", "")
        if it.get("text"):
            details = f"{it['text']}\n{details}"
        table.add_row(line, severity, issue, details)

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="FortiGate CLI heuristic syntax checker")
    parser.add_argument("input", type=Path, help="Path to CLI text file to check")
    parser.add_argument("--warnings", action="store_true", help="Include all warnings in output")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Input file not found: {args.input}")
        raise SystemExit(2)

    issues = analyze_file(args.input)
    print_issues_table(issues, include_warnings=args.warnings)
    # Exit code: 0 if no errors, 1 if any ERROR severity present, 2 if file missing (handled above)
    if any(i["severity"] == "ERROR" for i in issues):
        raise SystemExit(1)


if __name__ == "__main__":
        main()