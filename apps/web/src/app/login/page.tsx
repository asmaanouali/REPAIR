"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import {
  ShieldCheck,
  KeyRound,
  Mail,
  Loader2,
  Database,
  Terminal,
  FileSearch,
  Network,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { api, ApiError, type User } from "@/lib/api";

const LANGUAGES = [
  { name: "Java", versions: "8 — 21", icon: Database },
  { name: "Python", versions: "3.8 — 3.12", icon: Database },
];

const VULNERABILITIES: {
  cwe: string;
  title: string;
  blurb: string;
  icon: React.ComponentType<{ className?: string }>;
}[] = [
  {
    cwe: "CWE-89",
    title: "SQL Injection",
    blurb: "JDBC, JPA, Hibernate, MyBatis, Spring JdbcTemplate, Django ORM, PEP-249 DB-API",
    icon: Database,
  },
  {
    cwe: "CWE-78",
    title: "OS Command Injection",
    blurb: "Java ProcessBuilder / Runtime.exec, Python subprocess, os.system / os.popen",
    icon: Terminal,
  },
  {
    cwe: "CWE-90",
    title: "LDAP Injection",
    blurb: "JNDI LDAP, python-ldap, ldap3 — RFC 4515 filter parameterisation",
    icon: Network,
  },
  {
    cwe: "CWE-643",
    title: "XPath Injection",
    blurb: "javax.xml.xpath, lxml XPath — variable-bound expression evaluation",
    icon: FileSearch,
  },
];

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const m = useMutation({
    mutationFn: () => api.post<User>("/auth/login", { email, password }),
    onSuccess: () => {
      const next = params.get("next") || "/dashboard";
      router.replace(next);
    },
    onError: (e) => {
      setError(
        e instanceof ApiError && e.status === 401
          ? "Invalid credentials"
          : "Login failed",
      );
    },
  });

  return (
    <div className="glass w-full rounded-2xl p-8 animate-fade-in">
      <h1 className="mb-1 text-2xl font-semibold tracking-tight">Welcome back</h1>
      <p className="mb-6 text-sm text-muted-foreground">
        Sign in to your provable repair console.
      </p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          m.mutate();
        }}
        className="space-y-4"
      >
        <div>
          <Label htmlFor="email">Email</Label>
          <div className="relative mt-1">
            <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              id="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="pl-9"
              placeholder="owner@example.com"
            />
          </div>
        </div>
        <div>
          <Label htmlFor="password">Password</Label>
          <div className="relative mt-1">
            <KeyRound className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="pl-9"
              placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
            />
          </div>
        </div>

        {error && (
          <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}

        <Button type="submit" size="lg" className="w-full" disabled={m.isPending}>
          {m.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Sign in"}
        </Button>
      </form>

      
    </div>
  );
}

function ScopePanel() {
  return (
    <div className="glass w-full rounded-2xl p-8 animate-fade-in">
      <div className="mb-6">
        <h2 className="text-xl font-semibold tracking-tight">What IR-SAM repairs</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Sound, gate-validated patches for the injection family below — and
          only within the listed host languages. Anything else is an explicit
          abstention, never a silent rewrite.
        </p>
      </div>

      <div className="mb-6">
        <div className="mb-2 text-xs uppercase tracking-widest text-muted-foreground">
          Supported languages
        </div>
        <div className="flex flex-wrap gap-2">
          {LANGUAGES.map((l) => (
            <div
              key={l.name}
              className="flex items-center gap-2 rounded-lg border border-border bg-card/60 px-3 py-1.5 text-sm"
            >
              <l.icon className="h-4 w-4 text-cyan-300" />
              <span className="font-medium">{l.name}</span>
              <span className="font-mono text-[11px] text-muted-foreground">
                {l.versions}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <div className="mb-2 text-xs uppercase tracking-widest text-muted-foreground">
          Supported vulnerabilities
        </div>
        <ul className="space-y-2">
          {VULNERABILITIES.map((v) => (
            <li
              key={v.cwe}
              className="flex items-start gap-3 rounded-lg border border-border bg-card/40 px-3 py-2.5"
            >
              <div className="mt-0.5 rounded-md bg-primary/10 p-1.5 text-primary">
                <v.icon className="h-3.5 w-3.5" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline gap-2">
                  <span className="font-medium">{v.title}</span>
                  <span className="font-mono text-[10px] text-muted-foreground">
                    {v.cwe}
                  </span>
                </div>
                <p className="mt-0.5 text-xs text-muted-foreground">{v.blurb}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>

    
    </div>
  );
}

export default function LoginPage() {
  return (
    <main className="relative h-screen overflow-hidden bg-background">
      <div className="absolute inset-0 grid-bg opacity-30" />
      <div className="relative z-10 mx-auto flex h-full max-w-6xl flex-col p-6 lg:flex-row lg:gap-10">
        <div className="flex shrink-0 flex-col justify-center lg:w-[420px] lg:py-12">
          <div className="mb-8 flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-primary" />
            <span className="text-lg font-semibold tracking-tight">IR-SAM</span>
            <span className="ml-2 rounded-full border border-border px-2 py-0.5 text-[10px] uppercase tracking-widest text-muted-foreground">
              Java · Python
            </span>
          </div>
          <Suspense fallback={<div className="w-full rounded-2xl border border-border p-8 h-72" />}>
            <LoginForm />
          </Suspense>
        </div>

        <div className="flex-1 overflow-y-auto py-12">
          <ScopePanel />
        </div>
      </div>
    </main>
  );
}
