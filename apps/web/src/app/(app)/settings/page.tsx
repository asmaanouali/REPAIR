"use client";

import { useQuery } from "@tanstack/react-query";
import { Settings as SettingsIcon, ShieldCheck, Github } from "lucide-react";
import { api, type User } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

export default function SettingsPage() {
  const me = useQuery({ queryKey: ["me"], queryFn: () => api.get<User>("/auth/me") });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight flex items-center gap-2">
          <SettingsIcon className="h-6 w-6 text-primary" />Settings
        </h1>
        <p className="text-sm text-muted-foreground">Owner account and deployment configuration.</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Account</CardTitle>
            <CardDescription>Owner credentials are configured via the API <span className="font-mono">.env</span>.</CardDescription>
          </CardHeader>
          <CardContent>
            {me.isLoading ? <Skeleton className="h-16 w-full" /> : (
              <div className="space-y-2 text-sm">
                <Row k="Email" v={<span className="font-mono">{me.data?.email}</span>} />
                <Row k="Role"  v={<Badge tone="info">{me.data?.role}</Badge>} />
                <Row k="ID"    v={<span className="font-mono text-xs text-muted-foreground">{me.data?.id}</span>} />
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Github className="h-4 w-4" />GitHub integration</CardTitle>
            <CardDescription>Personal access tokens are entered per-PR and never stored.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row k="Provider" v={<Badge tone="info">GitHub</Badge>} />
            <Row k="Token storage" v={<Badge tone="success">ephemeral</Badge>} />
            <Row k="Required scope" v={<span className="font-mono text-xs">repo</span>} />
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-success" />Soundness guarantees</CardTitle>
            <CardDescription>Every patch published by IR-SAM is required to pass these gates.</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="grid gap-2 sm:grid-cols-2">
              {[
                "Parse equivalence (AST shape preserved)",
                "Semantic gate (interproc constants still reach sink)",
                "Sink-call rewrite confirmed (string-concat → parameterized)",
                "Validator gate (no taint left in trace)",
                "Abstention on failure (no false positives shipped)",
                "Reproducible randomness (seeded RNG)",
              ].map((t) => (
                <li key={t} className="flex items-center gap-2 rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs">
                  <ShieldCheck className="h-3 w-3 text-success" />{t}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-xs uppercase tracking-wide text-muted-foreground">{k}</span>
      <span>{v}</span>
    </div>
  );
}
