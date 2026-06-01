"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import { useMutation } from "@tanstack/react-query";
import { Wand2, ShieldCheck, ShieldAlert, Loader2 } from "lucide-react";
import { api, type QuickfixResult } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea, Label } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

const Editor = dynamic(
  () => import("@monaco-editor/react").then((m) => m.default),
  { ssr: false, loading: () => <Skeleton className="h-64 w-full" /> },
);

const LANGS = ["java", "python"] as const;
type Lang = (typeof LANGS)[number];

const SAMPLE: Record<Lang, string> = {
  java: `String userId = req.getParameter("id");\nString sql = "SELECT * FROM users WHERE id = " + userId;\nStatement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(sql);\n`,
  python: `cursor.execute("SELECT * FROM users WHERE id = " + request.args.get("id"))\n`,
};

export default function QuickfixPage() {
  const [language, setLanguage] = useState<Lang>("java");
  const [source, setSource] = useState(SAMPLE.java);

  const m = useMutation({
    mutationFn: () => api.post<QuickfixResult>("/quickfix", { language, source }),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight flex items-center gap-2">
          <Wand2 className="h-6 w-6 text-primary" />Quickfix
        </h1>
        <p className="text-sm text-muted-foreground">
          Paste a vulnerable snippet — get a provable, gate-validated patch in seconds.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Source</CardTitle>
              <div className="flex gap-1">
                {LANGS.map(l => (
                  <button key={l}
                    onClick={() => { setLanguage(l); setSource(SAMPLE[l]); }}
                    className={`rounded-md border px-2 py-1 text-[11px] capitalize transition-colors ${
                      language === l
                        ? "border-primary/50 bg-primary/10 text-primary"
                        : "border-border text-muted-foreground hover:bg-muted/40"
                    }`}>
                    {l}
                  </button>
                ))}
              </div>
            </div>
            <CardDescription>Up to 512 KB.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="overflow-hidden rounded-md border border-border">
              <Editor
                height="22rem"
                theme="vs-dark"
                language={language}
                value={source}
                onChange={(v) => setSource(v ?? "")}
                options={{
                  fontFamily: "var(--font-jetbrains), ui-monospace, Menlo",
                  fontSize: 13, minimap: { enabled: false }, wordWrap: "on",
                  scrollBeyondLastLine: false,
                }}
              />
            </div>
            <Button onClick={() => m.mutate()} disabled={m.isPending || !source.trim()}>
              {m.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <><Wand2 className="h-4 w-4" />Generate patch</>}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Result</CardTitle>
              {m.data && (
                <Badge tone={m.data.result.all_gates_passed ? "success" : m.data.result.patched ? "danger" : "warn"}>
                  {m.data.result.all_gates_passed ? "all gates passed" : m.data.result.patched ? "gate failed" : "abstained"}
                </Badge>
              )}
            </div>
            <CardDescription>
              {m.data
                ? <>Stage reached <span className="font-mono">{m.data.result.stage_reached}</span> · {m.data.elapsed_ms}ms</>
                : "Run a quickfix to see results."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!m.data ? (
              <div className="rounded-md border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
                Awaiting input.
              </div>
            ) : (
              <div className="space-y-4">
                {m.data.result.patched_source ? (
                  <div>
                    <div className="text-xs uppercase tracking-wide text-muted-foreground mb-1.5">Corrected code</div>
                    <pre className="max-h-80 overflow-auto rounded-md border border-border bg-background/60 p-3 text-[11px] font-mono leading-relaxed">
                      {m.data.result.patched_source}
                    </pre>
                  </div>
                ) : null}

                <div className="space-y-1.5">
                  <div className="text-xs uppercase tracking-wide text-muted-foreground">Gates</div>
                  <ul className="space-y-1">
                    {m.data.result.gates.map(g => (
                      <li key={g.name} className="rounded-md border border-border/60 bg-background/40 px-3 py-2 text-xs">
                        <div className="flex items-center justify-between gap-3">
                          <span className="flex items-center gap-2">
                            {g.passed
                              ? <ShieldCheck className="h-3 w-3 text-success" />
                              : <ShieldAlert className="h-3 w-3 text-destructive" />}
                            <span className="font-mono">{g.name}</span>
                          </span>
                          <span className={g.passed ? "text-success" : "text-destructive"}>{g.passed ? "pass" : "fail"}</span>
                        </div>
                        {g.detail ? (
                          <p className="mt-1.5 whitespace-pre-wrap break-words pl-5 text-[11px] leading-relaxed text-muted-foreground">
                            {g.detail}
                          </p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>

                {m.data.result.unified_diff ? (
                  <details className="group">
                    <summary className="cursor-pointer text-xs uppercase tracking-wide text-muted-foreground transition-colors hover:text-foreground">
                      Unified diff
                    </summary>
                    <pre className="mt-1.5 max-h-64 overflow-auto rounded-md border border-border bg-background/60 p-3 text-[11px] font-mono leading-relaxed">
                      {m.data.result.unified_diff}
                    </pre>
                  </details>
                ) : !m.data.result.patched_source ? (
                  <p className="rounded-md border border-dashed border-border p-3 text-xs text-muted-foreground">
                    {m.data.result.abstention_reason ?? "No diff produced."}
                  </p>
                ) : null}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
