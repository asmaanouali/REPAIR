"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FolderGit2, Plus, Loader2, Github, FileUp, X } from "lucide-react";
import { api, type Project } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { relativeTime, shortId } from "@/lib/utils";

type NewProject = {
  name: string;
  source_type: "upload" | "git" | "sarif";
  git_url?: string;
  default_branch?: string;
};

export default function ProjectsPage() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["projects"], queryFn: () => api.get<Project[]>("/projects"),
  });
  const [open, setOpen] = useState(false);

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Projects</h1>
          <p className="text-sm text-muted-foreground">Connect a repo or upload code, then trigger provable scans.</p>
        </div>
        <Button onClick={() => setOpen(true)}><Plus className="h-4 w-4" />New project</Button>
      </div>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[0,1,2].map(i => <Skeleton key={i} className="h-36 w-full" />)}
        </div>
      ) : (data ?? []).length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-3 py-16 text-center">
            <FolderGit2 className="h-10 w-10 text-muted-foreground" />
            <CardTitle>No projects yet</CardTitle>
            <CardDescription>Create your first project to start scanning.</CardDescription>
            <Button onClick={() => setOpen(true)} className="mt-2"><Plus className="h-4 w-4" />New project</Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {data!.map(p => (
            <Link key={p.id} href={`/projects/${p.id}`} className="group">
              <Card className="h-full transition-transform group-hover:-translate-y-0.5 group-hover:glow-ring">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-md bg-gradient-to-br from-primary/30 to-secondary/30">
                      {p.source_type === "git" ? <Github className="h-5 w-5 text-primary" /> : <FolderGit2 className="h-5 w-5 text-primary" />}
                    </div>
                    <div className="min-w-0">
                      <CardTitle className="truncate text-base">{p.name}</CardTitle>
                      <CardDescription className="truncate text-xs font-mono">{shortId(p.id)}</CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="flex items-center justify-between">
                  <Badge tone={p.source_type === "git" ? "info" : p.source_type === "sarif" ? "violet" : "neutral"}>
                    {p.source_type}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{relativeTime(p.created_at)}</span>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}

      {open && (
        <CreateProjectDialog
          onClose={() => setOpen(false)}
          onCreated={() => { setOpen(false); qc.invalidateQueries({ queryKey: ["projects"] }); }}
        />
      )}
    </div>
  );
}

function CreateProjectDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState<NewProject>({
    name: "", source_type: "git", git_url: "", default_branch: "main",
  });
  const [err, setErr] = useState<string | null>(null);

  const m = useMutation({
    mutationFn: () => api.post<Project>("/projects", form),
    onSuccess: onCreated,
    onError: (e: any) => setErr(e?.payload?.detail ?? "Could not create project"),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/70 backdrop-blur-sm" onClick={onClose}>
      <div className="glass w-full max-w-md rounded-2xl p-6 animate-fade-in" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">New project</h2>
          <Button size="icon" variant="ghost" onClick={onClose}><X className="h-4 w-4" /></Button>
        </div>
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); setErr(null); m.mutate(); }}>
          <div>
            <Label>Name</Label>
            <Input className="mt-1" required value={form.name} onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))} placeholder="acme-payments" />
          </div>

          <div>
            <Label>Source</Label>
            <div className="mt-1 grid grid-cols-3 gap-2">
              {(["git", "upload", "sarif"] as const).map(t => (
                <button type="button" key={t}
                  onClick={() => setForm(f => ({ ...f, source_type: t }))}
                  className={`rounded-md border px-3 py-2 text-xs capitalize transition-colors ${
                    form.source_type === t
                      ? "border-primary/50 bg-primary/10 text-primary"
                      : "border-border hover:bg-muted/40"
                  }`}>
                  {t === "git" ? <Github className="mx-auto mb-1 h-4 w-4" /> :
                   t === "upload" ? <FileUp className="mx-auto mb-1 h-4 w-4" /> :
                                    <FolderGit2 className="mx-auto mb-1 h-4 w-4" />}
                  {t}
                </button>
              ))}
            </div>
          </div>

          {form.source_type === "git" && (
            <>
              <div>
                <Label>Git URL</Label>
                <Input className="mt-1 font-mono" required
                  placeholder="https://github.com/org/repo"
                  value={form.git_url ?? ""}
                  onChange={(e) => setForm(f => ({ ...f, git_url: e.target.value }))} />
              </div>
              <div>
                <Label>Default branch</Label>
                <Input className="mt-1 font-mono"
                  value={form.default_branch ?? "main"}
                  onChange={(e) => setForm(f => ({ ...f, default_branch: e.target.value }))} />
              </div>
            </>
          )}

          {err && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">{err}</div>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={m.isPending}>
              {m.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Create"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
