// Smoke test for the JS Dockerfile-linter port. Run with: node index.test.js
import assert from "assert";
import { lint, splitBase, maxSeverity, parse } from "./index.js";

let passed = 0;
function ok(name, cond) {
  assert.ok(cond, name);
  passed++;
}

// splitBase mirrors the Python reference
{
  const [img, tag] = splitBase("node:12");
  ok("splitBase node:12", img === "node" && tag === "12");
}
{
  const [img, tag] = splitBase("python:3.11-slim AS build");
  ok("splitBase AS stage", img === "python" && tag === "3.11-slim");
}
{
  const [img, tag] = splitBase("registry.io:5000/team/app:1.2");
  ok("splitBase registry port", img === "app" && tag === "1.2");
}
{
  const [img, tag] = splitBase("ubuntu");
  ok("splitBase untagged", img === "ubuntu" && tag === null);
}

// EOL base -> SC120 critical
{
  const fs = lint('FROM node:12\nUSER app\nCMD ["node"]\n');
  const codes = fs.map((f) => f.code);
  ok("SC120 present for node:12", codes.includes("SC120"));
  ok("max severity critical", maxSeverity(fs) === "critical");
}

// root not dropped -> SC300
ok("SC300 for root", lint('FROM python:3.11-slim\nCMD ["x"]\n').some((f) => f.code === "SC300"));
ok("no SC300 when USER set", !lint('FROM python:3.11-slim\nUSER app\nCMD ["x"]\n').some((f) => f.code === "SC300"));

// secret detection -> SC230 critical
{
  const fs = lint("FROM alpine:3.19\nRUN export AWS_SECRET=abc123 && build\nUSER app\n");
  const s = fs.find((f) => f.code === "SC230");
  ok("SC230 secret critical", s && s.severity === "critical");
}

// curl | sh -> SC221
ok("SC221 curl-pipe-sh", lint("FROM alpine:3.19\nRUN curl https://x.sh | sh\nUSER app\n").some((f) => f.code === "SC221"));

// continuation merge: combined apt update+install does NOT flag SC201
{
  const text =
    "FROM python:3.11-slim\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends curl && \\\n    rm -rf /var/lib/apt/lists/*\nUSER app\n";
  const fs = lint(text);
  ok("no SC201 on combined RUN", !fs.some((f) => f.code === "SC201"));
  ok("parse merges continuations", parse(text).length === 3);
}

// unpinned tag -> SC101
ok("SC101 unpinned", lint("FROM ubuntu\nUSER app\n").some((f) => f.code === "SC101"));

console.log(`ok - ${passed} assertions passed`);
