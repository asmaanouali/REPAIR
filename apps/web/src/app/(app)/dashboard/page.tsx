"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  ShieldCheck, Activity, FolderGit2, AlertTriangle, GitPullRequest,
  ArrowUpRight, Sparkles,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge, StatusDot } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { api, type Project } from "@/lib/api";
import { relativeTime } from "@/lib/utils";

function Stat({
  icon: Icon, label, value, hint, tone = "primary",
}: { icon: any; label: string; value: React.ReactNode; hint?: string; tone?: "primary" | "violet" | "success" | "warn" }) {
  const toneClass = {
    primary: "from-primary/30 to-primary/0",
    violet:  "from-secondary/30 to-secondary/0",
    success: "from-success/30 to-success/0",
    warn:    "from-warning/30 to-warning/0",
  }[tone];
  return (
    <Card className="relative overflow-hidden">
      <div className={`absolute -right-12 -top-12 h-40 w-40 rounded-full bg-gradient-to-br ${toneClass} blur-2xl`} />
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardDescription>{label}</CardDescription>
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="text-3xl font-semibold tracking-tight">{value}</div>
        {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
      </CardContent>
    </Card>
  );
}

export default function DashboardPage() {
  const projects = useQuery({ queryKey: ["projects"], queryFn: () => api.get<Project[]>("/projects") });

  return (
    <div className="space-y-8">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Provable, auditable injection-vulnerability repair.
          </p>
        </div>
        <div className="flex gap-2">
          <Button asChild variant="outline"><Link href="/quickfix"><Sparkles className="h-4 w-4" />Quickfix</Link></Button>
          <Button asChild><Link href="/projects">View projects<ArrowUpRight className="h-4 w-4" /></Link></Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat icon={FolderGit2} label="Projects" value={projects.data?.length ?? "—"} hint="active workspaces" tone="primary" />
        <Stat icon={Activity}   label="Scans (24h)" value="0" hint="awaiting first scan" tone="violet" />
        <Stat icon={AlertTriangle} label="Open findings" value="0" tone="warn" />
        <Stat icon={GitPullRequest} label="PRs opened" value="0" hint="provable patches merged" tone="success" />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Recent projects</CardTitle>
              <Button asChild size="sm" variant="ghost"><Link href="/projects">See all</Link></Button>
            </div>
          </CardHeader>
          <CardContent>
            {projects.isLoading ? (
              <div className="space-y-3">
                {[0,1,2].map(i => <Skeleton key={i} className="h-12 w-full" />)}
              </div>
            ) : (projects.data ?? []).length === 0 ? (
              <div className="rounded-lg border border-dashed border-border p-8 text-center">
                <FolderGit2 className="mx-auto h-8 w-8 text-muted-foreground" />
                <p className="mt-3 text-sm text-muted-foreground">No projects yet.</p>
                <Button asChild className="mt-4"><Link href="/projects">Create one</Link></Button>
              </div>
            ) : (
              <ul className="divide-y divide-border/70">
                {projects.data!.slice(0, 6).map(p => (
                  <li key={p.id} className="group flex items-center justify-between py-3">
                    <Link href={`/projects/${p.id}`} className="flex min-w-0 items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-md bg-gradient-to-br from-primary/30 to-secondary/30">
                        <FolderGit2 className="h-4 w-4 text-primary" />
                      </div>
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium group-hover:text-primary">{p.name}</div>
                        <div className="truncate text-xs text-muted-foreground">
                          {p.source_type}{p.git_url ? ` · ${p.git_url}` : ""}
                        </div>
                      </div>
                    </Link>
                    <div className="text-xs text-muted-foreground">{relativeTime(p.created_at)}</div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>System</CardTitle>
            <CardDescription>Backend health & guarantees.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2"><StatusDot tone="success" />API</span>
              <Badge tone="success">online</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2"><StatusDot tone="info" />Worker</span>
              <Badge tone="info">ready</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2"><ShieldCheck className="h-3 w-3 text-success" />Validator gates</span>
              <Badge tone="success">enforced</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Languages</span>
              <span className="font-mono text-xs">java · py </span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
