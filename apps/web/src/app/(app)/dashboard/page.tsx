"use client";

import Link from "next/link";
import {
  ShieldCheck, Activity, AlertTriangle, GitPullRequest,
  Sparkles,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge, StatusDot } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

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
  // Projects feature hidden for demo — not in scope for this defense
  // const projects = useQuery({ queryKey: ["projects"], queryFn: () => api.get<Project[]>("/projects") });

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
          <Button asChild><Link href="/quickfix"><Sparkles className="h-4 w-4" />Open Quickfix</Link></Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {/* Projects stat hidden for demo */}
        <Stat icon={Activity}      label="Scans (24h)"   value="0" hint="awaiting first scan"      tone="violet" />
        <Stat icon={AlertTriangle} label="Open findings" value="0" hint="run a scan to populate"  tone="warn" />
        <Stat icon={GitPullRequest} label="Patches certified" value="0" hint="provable patches merged" tone="success" />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Recent projects panel hidden for demo */}

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
