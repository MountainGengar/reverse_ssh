#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
from pathlib import Path


def resolve_goroot(arg_goroot: str) -> Path:
    if arg_goroot:
        return Path(arg_goroot)

    env_goroot = os.environ.get("GOROOT")
    if env_goroot:
        return Path(env_goroot)

    try:
        out = subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()
    except FileNotFoundError as exc:
        raise SystemExit("go binary not found; set --goroot or GOROOT") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit("failed to run 'go env GOROOT'; set --goroot or GOROOT") from exc

    if not out:
        raise SystemExit("GOROOT is empty; set --goroot or GOROOT")

    return Path(out)


def patch_defs(path: Path) -> bool:
    text = path.read_text()
    if "SYS_EPOLL_WAIT" in text:
        return False

    anchor = "\tSYS_EPOLL_CTL     = 233\n"
    if anchor not in text:
        raise SystemExit(f"{path}: anchor not found (SYS_EPOLL_CTL)")

    text = text.replace(anchor, anchor + "\tSYS_EPOLL_WAIT    = 232\n")
    path.write_text(text)
    return True


def patch_syscall(path: Path) -> bool:
    text = path.read_text()
    if "if e == 38 { // ENOSYS" in text:
        return False

    needle = (
        "\tr1, _, e := Syscall6(SYS_EPOLL_PWAIT, uintptr(epfd), uintptr(ev), uintptr(maxev), uintptr(waitms), 0, 0)\n"
        "\treturn int32(r1), e"
    )
    if needle not in text:
        raise SystemExit(f"{path}: anchor not found (EpollWait body)")

    replacement = (
        "\tr1, _, e := Syscall6(SYS_EPOLL_PWAIT, uintptr(epfd), uintptr(ev), uintptr(maxev), uintptr(waitms), 0, 0)\n"
        "\tif e == 38 { // ENOSYS\n"
        "\t\tr1, _, e = Syscall6(SYS_EPOLL_WAIT, uintptr(epfd), uintptr(ev), uintptr(maxev), uintptr(waitms), 0, 0)\n"
        "\t}\n"
        "\treturn int32(r1), e"
    )

    path.write_text(text.replace(needle, replacement))
    return True


def patch_netpoll(path: Path) -> bool:
    text = path.read_text()
    if "ev.Events &^= syscall.EPOLLRDHUP" in text:
        return False

    old = "\treturn syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, int32(fd), &ev)"
    if old not in text:
        raise SystemExit(f"{path}: anchor not found (EpollCtl add)")

    new = (
        "\terrno := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, int32(fd), &ev)\n"
        "\tif errno == _EINVAL && ev.Events&syscall.EPOLLRDHUP != 0 {\n"
        "\t\tev.Events &^= syscall.EPOLLRDHUP\n"
        "\t\terrno = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, int32(fd), &ev)\n"
        "\t}\n"
        "\treturn errno"
    )

    path.write_text(text.replace(old, new))
    return True


def patch_detach(path: Path) -> bool:
    text = path.read_text()
    if "normalizeSelfPath" in text and "selfExecCandidates" in text:
        return False

    import_start = text.find("import (")
    if import_start == -1:
        raise SystemExit(f"{path}: import block not found")
    import_end = text.find(")\n", import_start)
    if import_end == -1:
        raise SystemExit(f"{path}: import block end not found")

    import_block = text[import_start:import_end + 2]
    import_lines = import_block.splitlines()
    indent = "\t"
    for line in import_lines[1:-1]:
        if line.strip():
            indent = line[: len(line) - len(line.lstrip())]
            break

    def has_import(name: str) -> bool:
        for line in import_lines[1:-1]:
            if line.strip().strip('"') == name:
                return True
        return False

    def find_import_line(name: str) -> int:
        for i, line in enumerate(import_lines):
            if line.strip().strip('"') == name:
                return i
        return -1

    for name in ("fmt", "os", "os/exec", "path/filepath", "strconv", "strings"):
        if has_import(name):
            continue
        insert_at = find_import_line("path/filepath")
        if insert_at == -1:
            insert_at = len(import_lines) - 1
        else:
            insert_at += 1
        import_lines.insert(insert_at, f"{indent}\"{name}\"")

    new_import_block = "\n".join(import_lines)
    text = text.replace(import_block, new_import_block, 1)

    run_anchor = "func Run(settings *client.Settings) {"
    if run_anchor not in text:
        raise SystemExit(f"{path}: anchor not found (Run)")

    helpers = (
        "func normalizeSelfPath(path string) string {\n"
        "\tif path == \"\" {\n"
        "\t\treturn \"\"\n"
        "\t}\n\n"
        "\tif unquoted, err := strconv.Unquote(path); err == nil {\n"
        "\t\tpath = unquoted\n"
        "\t} else {\n"
        "\t\tpath = strings.Trim(path, \"\\\"'\")\n"
        "\t}\n\n"
        "\treturn path\n"
        "}\n\n"
        "func isProcPath(path string) bool {\n"
        "\treturn strings.HasPrefix(path, \"/proc/\")\n"
        "}\n\n"
        "func selfExecCandidates(settings *client.Settings) []string {\n"
        "\tcandidates := make([]string, 0, 4)\n"
        "\tseen := make(map[string]bool)\n"
        "\tadd := func(path string) {\n"
        "\t\tpath = normalizeSelfPath(path)\n"
        "\t\tif path == \"\" || seen[path] {\n"
        "\t\t\treturn\n"
        "\t\t}\n"
        "\t\tif isProcPath(path) {\n"
        "\t\t\treturn\n"
        "\t\t}\n"
        "\t\tseen[path] = true\n"
        "\t\tcandidates = append(candidates, path)\n"
        "\t}\n\n"
        "\tif settings != nil && settings.SelfPath != \"\" {\n"
        "\t\tadd(settings.SelfPath)\n"
        "\t}\n\n"
        "\tif len(os.Args) > 0 && os.Args[0] != \"\" {\n"
        "\t\tif p, err := exec.LookPath(os.Args[0]); err == nil {\n"
        "\t\t\tadd(p)\n"
        "\t\t\tif abs, err := filepath.Abs(p); err == nil {\n"
        "\t\t\t\tadd(abs)\n"
        "\t\t\t}\n"
        "\t\t}\n\n"
        "\t\tif abs, err := filepath.Abs(os.Args[0]); err == nil {\n"
        "\t\t\tadd(abs)\n"
        "\t\t}\n"
        "\t}\n\n"
        "\tif p, err := os.Executable(); err == nil {\n"
        "\t\tadd(p)\n"
        "\t}\n\n"
        "\treturn candidates\n"
        "}\n\n"
    )

    text = text.replace(run_anchor, helpers + run_anchor, 1)

    fork_re = re.compile(
        r"func Fork\(settings \*client\.Settings, pretendArgv \.\.\.string\) error \{[\s\S]*?\n\}"
    )
    if not fork_re.search(text):
        raise SystemExit(f"{path}: Fork function not found for replacement")

    fork_new = (
        "func Fork(settings *client.Settings, pretendArgv ...string) error {\n\n"
        "\tlog.Println(\"Forking\")\n\n"
        "\tcandidates := selfExecCandidates(settings)\n"
        "\tif len(candidates) == 0 {\n"
        "\t\treturn fmt.Errorf(\"unable to resolve self path for re-exec\")\n"
        "\t}\n\n"
        "\tvar lastErr error\n"
        "\tfor _, candidate := range candidates {\n"
        "\t\terr := fork(candidate, nil, pretendArgv...)\n"
        "\t\tif err == nil {\n"
        "\t\t\treturn nil\n"
        "\t\t}\n\n"
        "\t\tlog.Println(\"Forking from\", candidate, \"failed:\", err)\n"
        "\t\tlastErr = err\n"
        "\t}\n\n"
        "\treturn lastErr\n"
        "}\n"
    )

    text = fork_re.sub(fork_new, text, count=1)
    path.write_text(text)
    return True


def patch_client_settings(path: Path) -> bool:
    text = path.read_text()
    if "SelfPath" in text:
        return False

    anchor = "\tSNI         string\n"
    if anchor not in text:
        raise SystemExit(f"{path}: anchor not found (SNI field)")

    insert = anchor + "\tSelfPath    string\n"
    text = text.replace(anchor, insert, 1)
    path.write_text(text)
    return True


def patch_buildmanager(path: Path) -> bool:
    text = path.read_text()
    if "SelfPath" in text and "main.selfPath" in text:
        return False

    field_anchor = "\tProxy, SNI, LogLevel string\n"
    if field_anchor in text and "SelfPath" not in text:
        text = text.replace(field_anchor, field_anchor + "\tSelfPath string\n", 1)
    elif "SelfPath" not in text:
        raise SystemExit(f"{path}: anchor not found (Proxy/SNI/LogLevel fields)")

    ldflag_anchor = "-X main.customSNI=%s -X main.useHostKerberos=%t"
    if ldflag_anchor in text and "main.selfPath" not in text:
        text = text.replace(ldflag_anchor, "-X main.customSNI=%s -X main.selfPath=%s -X main.useHostKerberos=%t", 1)

    args_anchor = "config.Proxy, config.SNI, config.UseKerberosAuth"
    if args_anchor in text and "config.SelfPath" not in text:
        text = text.replace(args_anchor, "config.Proxy, config.SNI, config.SelfPath, config.UseKerberosAuth", 1)

    path.write_text(text)
    return True


def patch_link_command(path: Path) -> bool:
    text = path.read_text()
    if "self-path" in text and "SelfPath" in text:
        return False

    # Add flag description
    sni_flag = "\t\t\"sni\":               \"When TLS is in use, set a custom SNI for the client to connect with\",\n"
    if sni_flag in text and "self-path" not in text:
        text = text.replace(
            sni_flag,
            sni_flag + "\t\t\"self-path\":         \"Explicit path to the client binary for re-exec on daemonize\",\n",
            1,
        )

    # Parse flag into buildConfig
    sni_parse = "\tbuildConfig.SNI, err = line.GetArgString(\"sni\")\n"
    if sni_parse in text and "self-path" not in text:
        insert = (
            sni_parse
            + "\tif err != nil && err != terminal.ErrFlagNotSet {\n"
            + "\t\treturn err\n"
            + "\t}\n\n"
            + "\tbuildConfig.SelfPath, err = line.GetArgString(\"self-path\")\n"
            + "\tif err != nil && err != terminal.ErrFlagNotSet {\n"
            + "\t\treturn err\n"
            + "\t}\n"
        )
        text = text.replace(
            sni_parse
            + "\tif err != nil && err != terminal.ErrFlagNotSet {\n\t\treturn err\n\t}\n",
            insert,
            1,
        )

    path.write_text(text)
    return True


def patch_main(path: Path) -> bool:
    text = path.read_text()
    if "GetArgString(\"self-path\")" in text and "SelfPath" in text and "--self-path" in text:
        return False

    updated = False

    usage_old = "--[foreground|fingerprint|proxy|process_name]"
    if usage_old in text:
        text = text.replace(usage_old, "--[foreground|fingerprint|proxy|process_name|self-path]", 1)
        updated = True

    if "--self-path" not in text:
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if "--sni\\tWhen using TLS" in line:
                lines.insert(
                    i + 1,
                    "\tfmt.Println(\"\\t\\t--self-path\\tExplicit path to the client binary for re-exec on daemonize\")",
                )
                text = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
                updated = True
                break

    var_anchor = "\tcustomSNI   string\n"
    if var_anchor in text and "selfPath" not in text:
        text = text.replace(var_anchor, var_anchor + "\tselfPath    string\n", 1)
        updated = True

    settings_anchor = "\t\tSNI:                  customSNI,\n"
    if settings_anchor in text and "SelfPath" not in text:
        text = text.replace(settings_anchor, settings_anchor + "\t\tSelfPath:             selfPath,\n", 1)
        updated = True

    parse_anchor = "\tproxyaddress, _ := line.GetArgString(\"proxy\")\n"
    if parse_anchor in text and "GetArgString(\"self-path\")" not in text:
        insert = (
            parse_anchor
            + "\tif len(proxyaddress) > 0 {\n"
            + "\t\tsettings.ProxyAddr = proxyaddress\n"
            + "\t}\n\n"
            + "\tuserSpecifiedSelfPath, err := line.GetArgString(\"self-path\")\n"
            + "\tif err == nil {\n"
            + "\t\tsettings.SelfPath = userSpecifiedSelfPath\n"
            + "\t}\n"
        )
        text = text.replace(
            parse_anchor + "\tif len(proxyaddress) > 0 {\n\t\tsettings.ProxyAddr = proxyaddress\n\t}\n",
            insert,
            1,
        )
        updated = True

    if updated:
        path.write_text(text)
        return True

    return False


def validate_repo(repo_root: Path) -> None:
    checks = [
        (repo_root / "internal/client/client.go", "SelfPath"),
        (repo_root / "cmd/client/main.go", "--self-path"),
        (repo_root / "cmd/client/detach.go", "selfExecCandidates"),
        (repo_root / "cmd/client/detach.go", "normalizeSelfPath"),
        (repo_root / "cmd/client/detach.go", "isProcPath"),
        (repo_root / "internal/server/commands/link.go", "self-path"),
        (repo_root / "internal/server/webserver/buildmanager.go", "main.selfPath"),
        (repo_root / "internal/server/webserver/buildmanager.go", "SelfPath"),
    ]
    missing = []
    for path, needle in checks:
        if not path.exists():
            missing.append(f"{path} does not exist")
            continue
        if needle not in path.read_text():
            missing.append(f"{path} missing {needle}")

    if missing:
        raise SystemExit(
            "repo missing self-path/forking patch:\n- " + "\n- ".join(missing)
        )

    print("repo: self-path/forking patch present")


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch Go runtime for ESXi epoll quirks")
    parser.add_argument("--goroot", help="GOROOT path (defaults to GOROOT env or 'go env GOROOT')")
    parser.add_argument("--repo", help="Repo root to validate for self-path/forking patch")
    args = parser.parse_args()

    goroot = resolve_goroot(args.goroot)

    defs_path = goroot / "src/internal/runtime/syscall/defs_linux_amd64.go"
    syscall_path = goroot / "src/internal/runtime/syscall/syscall_linux.go"
    netpoll_path = goroot / "src/runtime/netpoll_epoll.go"

    for p in (defs_path, syscall_path, netpoll_path):
        if not p.exists():
            raise SystemExit(f"{p} does not exist")

    patched = []
    if patch_defs(defs_path):
        patched.append(str(defs_path))
    if patch_syscall(syscall_path):
        patched.append(str(syscall_path))
    if patch_netpoll(netpoll_path):
        patched.append(str(netpoll_path))

    if patched:
        print("patched:")
        for p in patched:
            print("-", p)
    else:
        print("already patched")

    if args.repo:
        repo_root = Path(args.repo)
        detach_path = repo_root / "cmd/client/detach.go"
        main_path = repo_root / "cmd/client/main.go"
        client_path = repo_root / "internal/client/client.go"
        link_path = repo_root / "internal/server/commands/link.go"
        build_path = repo_root / "internal/server/webserver/buildmanager.go"

        for p in (detach_path, main_path, client_path, link_path, build_path):
            if not p.exists():
                raise SystemExit(f"{p} does not exist")

        repo_patched = []
        if patch_detach(detach_path):
            repo_patched.append(str(detach_path))
        if patch_main(main_path):
            repo_patched.append(str(main_path))
        if patch_client_settings(client_path):
            repo_patched.append(str(client_path))
        if patch_link_command(link_path):
            repo_patched.append(str(link_path))
        if patch_buildmanager(build_path):
            repo_patched.append(str(build_path))

        if repo_patched:
            print("repo patched:")
            for p in repo_patched:
                print("-", p)
        else:
            print("repo already patched")

        validate_repo(repo_root)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
