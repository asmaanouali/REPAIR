"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Activity, AlertTriangle, FileCode } from "lucide-react";
import { api, type Scan, type Finding } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge, StatusDot } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { relativeTime, shortId } from "@/lib/utils";

const STATUS_TONE: Record<string, "info" | "violet" | "success" | "danger" | "neutral"> = {
  queued: "neutral", running: "info", succeeded: "success", failed: "danger", cancelled: "violet",
};

type ScanEvent = { id: string; status: string; stats: Record<string, unknown> };

export default function ScanDetail({ params }: { params: { id: string } }) {
  const { id } = params;

  const scan = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.get<Scan>(`/scans/${id}`),
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s === "running" || s === "queued" ? 2000 : false;
    },
  });
  const findings = useQuery({
    queryKey: ["scan-findings", id],
    queryFn: () => api.get<Finding[]>(`/scans/${id}/findings`),
    refetchInterval: 3000,
  });

  // Live SSE event log
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const closedRef = useRef(false);
  useEffect(() => {
    const es = new EventSource(`/api/scans/${id}/events`, { withCredentials: true });
    es.onmessage = (ev) => {
      try { setEvents((arr) => [...arr, JSON.parse(ev.data)]); } catch { /* ignore */ }
    };
    es.onerror = () => { if (!closedRef.current) es.close(); };
    return () => { closedRef.current = true; es.close(); };
  }, [id]);

  if (scan.isLoading) return <Skeleton className="h-40 w-full" />;
  if (!scan.data) return <p className="text-sm text-muted-foreground">Scan not found.</p>;
  const s = scan.data;

  return (
    <div className="space-y-6">
      <div className="text-sm text-muted-foreground">
        <Link href={`/projects/${s.project_id}`} className="inline-flex items-center gap-1 hover:text-foreground">
          <ArrowLeft className="h-3 w-3" />Project
        </Link>
      </div>

      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Scan {shortId(s.id)}</h1>
          <p className="text-xs text-muted-foreground font-mono">{s.id}</p>
        </div>
        <div className="flex items-center gap-3">
          <StatusDot tone={STATUS_TONE[s.status] ?? "neutral"} />
          <Badge tone={STATUS_TONE[s.status] ?? "neutral"}>{s.status}</Badge>
          <span className="text-xs text-muted-foreground">started {relativeTime(s.started_at ?? s.created_at)}</span>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2"><Activity className="h-4 w-4" />Live events</CardTitle>
            <CardDescription>Streamed from the scan worker.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="max-h-[28rem] overflow-y-auto rounded-md bg-background/60 p-3 font-mono text-xs">
              {events.length === 0 ? (
                <div className="text-muted-foreground">Waiting for first event…</div>
              ) : events.map((e, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="text-muted-foreground">{String(i+1).padStart(3, "0")}</span>
                  <Badge tone={STATUS_TONE[e.status] ?? "neutral"}>{e.status}</Badge>
                  <span className="truncate text-muted-foreground">{JSON.stringify(e.stats)}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2"><AlertTriangle className="h-4 w-4" />Findings</CardTitle>
              <Badge tone="violet">{findings.data?.length ?? 0}</Badge>
            </div>
            <CardDescription>Each finding gets a provable patch proposal.</CardDescription>
          </CardHeader>
          <CardContent>
            {findings.isLoading ? (
              <Skeleton className="h-24 w-full" />
            ) : (findings.data ?? []).length === 0 ? (
              <p className="rounded-md border border-dashed border-border p-6 text-center text-sm text-muted-foreground">
                No findings yet.
              </p>
            ) : (
              <ul className="divide-y divide-border/70">
                {findings.data!.map(f => (
                  <li key={f.id}>
                    <Link href={`/findings/${f.id}`} className="group block py-3">
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex min-w-0 items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-warning/15 text-warning">
                            <FileCode className="h-4 w-4" />
                          </div>
                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium group-hover:text-primary">{f.sink_api}</div>
                            <div className="truncate text-xs text-muted-foreground font-mono">{f.file_path}:{f.line}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge tone="violet">{f.cwe}</Badge>
                          <Badge tone={f.state === "open" ? "warn" : f.state === "wont_fix" ? "danger" : "neutral"}>{f.state}</Badge>
                        </div>
                      </div>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
