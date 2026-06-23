package main

import "testing"

func hasCode(fs []Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestSplitBase(t *testing.T) {
	cases := []struct {
		in    string
		image string
		tag   string
	}{
		{"node:12", "node", "12"},
		{"python:3.11-slim AS build", "python", "3.11-slim"},
		{"registry.io:5000/team/app:1.2", "app", "1.2"},
		{"ubuntu", "ubuntu", ""},
	}
	for _, c := range cases {
		img, tag := splitBase(c.in)
		if img != c.image || tag != c.tag {
			t.Errorf("splitBase(%q) = (%q,%q), want (%q,%q)", c.in, img, tag, c.image, c.tag)
		}
	}
}

func TestEolCveCritical(t *testing.T) {
	fs := lint("FROM node:12\nUSER app\nCMD [\"node\"]\n")
	if !hasCode(fs, "SC120") {
		t.Fatal("expected SC120 for node:12")
	}
	if maxSeverity(fs) != "critical" {
		t.Fatalf("expected critical, got %q", maxSeverity(fs))
	}
}

func TestRootUserFlagged(t *testing.T) {
	if !hasCode(lint("FROM python:3.11-slim\nCMD [\"x\"]\n"), "SC300") {
		t.Fatal("expected SC300 when root not dropped")
	}
}

func TestRootDroppedOk(t *testing.T) {
	if hasCode(lint("FROM python:3.11-slim\nUSER app\nCMD [\"x\"]\n"), "SC300") {
		t.Fatal("did not expect SC300 when USER set")
	}
}

func TestSecretDetection(t *testing.T) {
	fs := lint("FROM alpine:3.19\nRUN export AWS_SECRET=abc123 && build\nUSER app\n")
	if !hasCode(fs, "SC230") {
		t.Fatal("expected SC230 secret finding")
	}
}

func TestCurlPipeSh(t *testing.T) {
	if !hasCode(lint("FROM alpine:3.19\nRUN curl https://x.sh | sh\nUSER app\n"), "SC221") {
		t.Fatal("expected SC221 curl|sh finding")
	}
}

func TestContinuationMerge(t *testing.T) {
	text := "FROM python:3.11-slim\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends curl && \\\n    rm -rf /var/lib/apt/lists/*\nUSER app\n"
	if hasCode(lint(text), "SC201") {
		t.Fatal("combined apt update+install should not flag SC201")
	}
	if len(parse(text)) != 3 {
		t.Fatalf("expected 3 instructions after merge, got %d", len(parse(text)))
	}
}

func TestUnpinnedTag(t *testing.T) {
	if !hasCode(lint("FROM ubuntu\nUSER app\n"), "SC101") {
		t.Fatal("expected SC101 for unpinned tag")
	}
}
