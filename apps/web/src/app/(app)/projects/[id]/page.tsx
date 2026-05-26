"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft, Play, Activity, FileUp, FolderGit2, Loader2, Github,
  Trash2, Settings as SettingsIcon,
} from "lucide-react";
import { api, type Project, type Scan } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge, StatusDot } from "@/components/ui/badge";
import { relativeTime, shortId } from "@/lib/utils";
import { useRouter } from "next/navigation";

const STATUS_TONE: Record<string, "info" | "violet" | "success" | "danger" | "neutral"> = {
  queued: "neutral", running: "info", succeeded: "success", failed: "danger", cancelled: "violet",
};

export default function ProjectDetail({ params }: { params: { id: string } }) {
  const { id } = params;
  const router = useRouter();
  const qc = useQueryClient();

  const project = useQuery({ queryKey: ["project", id], queryFn: () => api.get<Project>(`/projects/${id}`) });
  const scans   = useQuery({ queryKey: ["scans", id],   queryFn: () => api.get<Scan[]>(`/projects/${id}/scans`),
                             refetchInterval: 5000 });

  const [sourcePath, setSourcePath] = useState("");
  const startScan = useMutation({
    mutationFn: () =>
      api.post<Scan>(`/projects/${id}/scans`, {
        trigger: "manual",
        source_path: sourcePath || undefined,
      }),
    onSuccess: (s) => { qc.invalidateQueries({ queryKey: ["scans", id] }); router.push(`/scans/${s.id}`); },
  });

  const remove = useMutation({
    mutationFn: () => api.del<void>(`/projects/${id}`),
    onSuccess: () => router.replace("/projects"),
  });

  if (project.isLoading) return <Skeleton className="h-40 w-full" />;
  if (!project.data) return <p className="text-sm text-muted-foreground">Project not found.</p>;
  const p = project.data;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Link href="/projects" className="inline-flex items-center gap-1 hover:text-foreground">
          <ArrowLeft className="h-3 w-3" />Projects
        </Link>
      </div>

      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-gradient-to-br from-primary/30 to-secondary/30">
            {p.source_type === "git" ? <Github className="h-6 w-6 text-primary" /> : <FolderGit2 className="h-6 w-6 text-primary" />}
          </div>
          <div>
            <h1 className="text-3xl font-semibold tracking-tight">{p.name}</h1>
            <p className="text-xs text-muted-foreground font-mono">{p.id}</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="icon" title="Delete project" onClick={() => {
            if (confirm("Delete this project? This cannot be undone.")) remove.mutate();
          }}>
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Trigger a scan</CardTitle>
            <CardDescription>Run the IR-SAM pipeline against a local path on the worker host.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Label htmlFor="path">Source path</Label>
            <div className="flex gap-2">
              <Input id="path" value={sourcePath} onChange={(e) => setSourcePath(e.target.value)}
                placeholder="/srv/repos/acme-payments  (leave blank for empty placeholder scan)"
                className="font-mono" />
              <Button onClick={() => startScan.mutate()} disabled={startScan.isPending}>
                {startScan.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <><Play className="h-4 w-4" />Start</>}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Tip: for Git projects, the worker will clone <span className="font-mono">{p.git_url ?? "—"}</span>
              {p.default_branch ? <> @ <span className="font-mono">{p.default_branch}</span></> : null} into a temporary
              directory in a future release. Until then, point to an existing path on disk.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2"><SettingsIcon className="h-4 w-4" />Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row k="Source"   v={<Badge tone={p.source_type === "git" ? "info" : "neutral"}>{p.source_type}</Badge>} />
            {p.git_url && <Row k="Git URL" v={<span className="font-mono text-xs">{p.git_url}</span>} />}
            {p.default_branch && <Row k="Branch" v={<span className="font-mono text-xs">{p.default_branch}</span>} />}
            <Row k="Created" v={relativeTime(p.created_at)} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4" />Scans</CardTitle>
          <CardDescription>Updated every 5s.</CardDescription>
        </CardHeader>
        <CardContent>
          {scans.isLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : (scans.data ?? []).length === 0 ? (
            <p className="rounded-md border border-dashed border-border p-6 text-center text-sm text-muted-foreground">
              No scans yet.
            </p>
          ) : (
            <ul className="divide-y divide-border/70">
              {scans.data!.map(s => (
                <li key={s.id}>
                  <Link href={`/scans/${s.id}`} className="group flex items-center justify-between py-3">
                    <div className="flex min-w-0 items-center gap-3">
                      <StatusDot tone={STATUS_TONE[s.status] ?? "neutral"} />
                      <div className="min-w-0">
                        <div className="truncate text-sm font-mono">{shortId(s.id)}</div>
                        <div className="text-xs text-muted-foreground">trigger: {s.trigger}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge tone={STATUS_TONE[s.status] ?? "neutral"}>{s.status}</Badge>
                      <span className="text-xs text-muted-foreground">{relativeTime(s.created_at)}</span>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
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
