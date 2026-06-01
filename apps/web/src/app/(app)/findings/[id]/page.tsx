"use client";

import { useMemo, useState } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft, ShieldCheck, ShieldAlert, Github, GitPullRequest,
  Loader2, X, ChevronDown, FileCode, Wand2, CheckCircle2,
} from "lucide-react";
import { api, type Finding, type PatchProposal } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { cn, relativeTime, shortId } from "@/lib/utils";

const DiffEditor = dynamic(
  () => import("@monaco-editor/react").then((m) => m.DiffEditor),
  { ssr: false, loading: () => <Skeleton className="h-[28rem] w-full" /> },
);

const STATE_TONE: Record<string, "info" | "warn" | "success" | "danger" | "violet" | "neutral"> = {
  open: "warn", dismissed: "neutral", wont_fix: "danger",
};
const PATCH_TONE: Record<string, "info" | "warn" | "success" | "danger" | "violet" | "neutral"> = {
  pending_review: "info", approved: "success", rejected: "danger",
  open_pr: "violet", merged: "success", applied: "success",
};

// Best-effort patches embed this marker in the inserted comment block so
// the UI can flag them without an extra API field.
const BEST_EFFORT_MARKER = "IR-SAM best-effort remediation hint";
function isBestEffort(diff: string | null | undefined): boolean {
  return !!diff && diff.includes(BEST_EFFORT_MARKER);
}

/** Translate a pipeline abstention into a human-readable title + detail. */
function abstentionCopy(stage: string, reason: string | null | undefined): { title: string; detail: string } {
  const r = reason ?? "";

  // Stage A — language / file-level problems
  if (stage === "A") {
    if (r.startsWith("unsupported_backend:"))
      return {
        title: "Unsupported language",
        detail: `IR-SAM has no backend registered for this language/interpreter pair (${r.replace("unsupported_backend:", "")}). Only Java and Python sources with SQL, XPath, LDAP, or shell sinks are currently supported.`,
      };
    if (r === "no_sink_found")
      return {
        title: "No injection sink found",
        detail: "IR-SAM scanned the file but found no dangerous call sites (raw query concatenation, shell execution, etc.) matching its supported patterns.",
      };
    if (r === "finding_file_not_found")
      return {
        title: "Source file not found",
        detail: "The file referenced by this finding does not exist on disk. It may have been moved, deleted, or the project root is misconfigured.",
      };
    if (r.startsWith("finding_file_unreadable"))
      return {
        title: "Source file unreadable",
        detail: `The file could not be read (${r.replace("finding_file_unreadable:", "").trim()}). Check file permissions or encoding.`,
      };
  }

  // Stage B — slicing
  if (stage === "B")
    return {
      title: "Data-flow slice failed",
      detail: `IR-SAM located the sink but could not trace the tainted data-flow path leading into it${r ? ` (${r})` : ""}. The call may be too deeply nested or use an unsupported control-flow pattern.`,
    };

  // Stage C — template reconstruction
  if (stage === "C")
    return {
      title: "Template reconstruction failed",
      detail: `The slicer produced a fragment but IR-SAM could not reconstruct a parameterized query template from it${r ? ` (${r})` : ""}. The query may be dynamically composed in a way the reconstructor cannot handle.`,
    };

  // Stage D — parsing / grammar
  if (stage === "D") {
    if (r.includes("ambiguous_intent"))
      return {
        title: "Ambiguous query intent",
        detail: "IR-SAM extracted a query template but could not determine its structural intent (SELECT vs. INSERT vs. …). The disambiguator was consulted but did not resolve the ambiguity. A best-effort patch cannot be safely produced.",
      };
    if (r.includes("sql0_syntax") || r.includes("_parse:"))
      return {
        title: "Query template unparseable",
        detail: `The reconstructed template does not conform to IR-SAM's supported query grammar${r ? ` (${r.split(":").slice(1).join(":").trim()})` : ""}. Inline expressions, stored-procedure calls, or dialect-specific syntax may be the cause.`,
      };
    return {
      title: "Parse-stage abstention",
      detail: `IR-SAM could not structurally parse the query at the sink${r ? ` (${r})` : ""}. The system abstains to avoid producing an incorrect fix.`,
    };
  }

  // Stage E — binder / catalog mapping
  if (stage === "E")
    return {
      title: "No safe parameterizing API found",
      detail: `IR-SAM parsed the query successfully but could not map its holes to a safe, parameterized API from the binder catalog${r ? ` (${r})` : ""}. The framework may not be in the catalog, or the query structure is unsupported.`,
    };

  // Stage F — rewrite / synthesis
  if (stage === "F")
    return {
      title: "Patch synthesis failed",
      detail: `IR-SAM selected a parameterizing API but could not synthesize the final source rewrite${r ? ` (${r})` : ""}. The code structure at the call site may prevent automated rewriting.`,
    };

  // Fallback
  return {
    title: "Pipeline abstained",
    detail: `The pipeline stopped at stage ${stage}${r ? ` with reason: ${r}` : ""}.`,
  };
}

export default function FindingDetail({ params }: { params: { id: string } }) {
  const { id } = params;
  const qc = useQueryClient();
  const finding = useQuery({ queryKey: ["finding", id], queryFn: () => api.get<Finding>(`/findings/${id}`) });
  const patches = useQuery({
    queryKey: ["finding-patches", id],
    queryFn: () => api.get<PatchProposal[]>(`/findings/${id}/patches`),
  });

  const latest = useMemo(
    () => (patches.data ?? []).slice().sort((a, b) => +new Date(b.created_at) - +new Date(a.created_at))[0],
    [patches.data],
  );

  const setState = useMutation({
    mutationFn: (state: "open" | "dismissed" | "wont_fix") =>
      api.patch<Finding>(`/findings/${id}`, { state }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", id] }),
  });

  if (finding.isLoading) return <Skeleton className="h-40 w-full" />;
  if (!finding.data) return <p className="text-sm text-muted-foreground">Finding not found.</p>;
  const f = finding.data;

  return (
    <div className="space-y-6">
      <div className="text-sm text-muted-foreground">
        <Link href={`/scans/${f.scan_id}`} className="inline-flex items-center gap-1 hover:text-foreground">
          <ArrowLeft className="h-3 w-3" />Scan
        </Link>
      </div>

      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Badge tone="violet">{f.cwe}</Badge>
            <span className="font-mono">{f.rule_id}</span>
            <span>·</span>
            <span>severity: {f.severity}</span>
          </div>
          <h1 className="mt-1 truncate text-3xl font-semibold tracking-tight">{f.sink_api}</h1>
          <p className="truncate text-sm text-muted-foreground font-mono">{f.file_path}:{f.line}</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge tone={STATE_TONE[f.state] ?? "neutral"}>{f.state}</Badge>
          <StateMenu current={f.state} onChange={(s) => setState.mutate(s)} disabled={setState.isPending} />
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Proposed patch</CardTitle>
              <div className="flex items-center gap-2">
                {latest && isBestEffort(latest.unified_diff) && (
                  <Badge tone="warn">best-effort</Badge>
                )}
                {latest && <Badge tone={PATCH_TONE[latest.status] ?? "neutral"}>{latest.status}</Badge>}
              </div>
            </div>
            <CardDescription>
              {latest
                ? <>Reached stage <span className="font-mono">{latest.stage_reached}</span> · {relativeTime(latest.created_at)}</>
                : "No patch proposal yet."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!latest ? (
              <p className="rounded-md border border-dashed border-border p-6 text-center text-sm text-muted-foreground">
                Waiting for the worker to generate a patch.
              </p>
            ) : !latest.unified_diff ? (
              (() => {
                const { title, detail } = abstentionCopy(latest.stage_reached, latest.plan?.abstention_reason);
                return (
                  <div className="rounded-md border border-dashed border-border p-6 text-sm text-muted-foreground space-y-2">
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-foreground">{title}</p>
                      <span className="font-mono text-xs bg-muted text-muted-foreground rounded px-1.5 py-0.5">stage {latest.stage_reached}</span>
                    </div>
                    <p>{detail}</p>
                    {latest.plan?.abstention_reason && (
                      <p className="text-xs font-mono bg-muted rounded px-2 py-1 break-all">{latest.plan.abstention_reason}</p>
                    )}
                  </div>
                );
              })()
            ) : (
              <>
                {isBestEffort(latest.unified_diff) && (
                  <div className="mb-3 rounded-md border border-warning/30 bg-warning/10 px-3 py-2 text-xs text-warning">
                    The principled rewriter could not produce a provable fix, so IR-SAM has inserted a remediation hint at the sink for human review. Approve to apply the annotation, or reject and patch manually using the hint as guidance.
                  </div>
                )}
                <PatchDiff diff={latest.unified_diff} fileName={f.file_path} />
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Decision</CardTitle>
            <CardDescription>Approve the generated patch to apply it.</CardDescription>
          </CardHeader>
          <CardContent>
            {latest ? (
              <DecisionPanel patch={latest} findingId={f.id} />
            ) : (
              <p className="text-sm text-muted-foreground">No patch to decide on yet.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {latest && <ProofPanel patch={latest} />}
    </div>
  );
}

function PatchDiff({ diff, fileName }: { diff: string; fileName: string }) {
  // Reconstruct "before" and "after" from the unified diff so Monaco can show
  // a side-by-side view. For a research artifact this is best-effort.
  const { before, after } = useMemo(() => splitUnifiedDiff(diff), [diff]);
  const language = useMemo(() => guessLanguage(fileName), [fileName]);

  return (
    <div className="overflow-hidden rounded-md border border-border">
      <div className="flex items-center justify-between border-b border-border bg-background/60 px-3 py-2 text-xs">
        <div className="flex items-center gap-2 text-muted-foreground">
          <FileCode className="h-3 w-3" /><span className="font-mono">{fileName}</span>
        </div>
        <Badge tone="info">unified diff</Badge>
      </div>
      <DiffEditor
        height="28rem"
        theme="vs-dark"
        original={before}
        modified={after}
        language={language}
        options={{
          readOnly: true, renderSideBySide: true, minimap: { enabled: false },
          fontFamily: "var(--font-jetbrains), ui-monospace, Menlo",
          fontSize: 12, scrollBeyondLastLine: false, wordWrap: "on",
        }}
      />
    </div>
  );
}

function DecisionPanel({ patch, findingId }: { patch: PatchProposal; findingId: string }) {
  const qc = useQueryClient();
  const [prOpen, setPrOpen] = useState(false);
  const [applyErr, setApplyErr] = useState<string | null>(null);

  const decide = useMutation({
    mutationFn: (status: "approved" | "rejected") =>
      api.post<PatchProposal>(`/patches/${patch.id}/decision`, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding-patches", findingId] }),
  });

  const apply = useMutation({
    mutationFn: () => api.post<PatchProposal>(`/patches/${patch.id}/apply`, {}),
    onSuccess: () => {
      setApplyErr(null);
      qc.invalidateQueries({ queryKey: ["finding-patches", findingId] });
    },
    onError: (e: any) => setApplyErr(e?.payload?.detail ?? "Could not apply patch"),
  });

  const status = patch.status;
  const hasDiff = Boolean(patch.unified_diff);
  const isApplied = status === "applied";
  return (
    <div className="space-y-3">
      {!hasDiff && (
        <div className="rounded-md border border-warning/30 bg-warning/10 px-3 py-2 text-xs text-warning">
          No patch code was generated for this finding — nothing to approve or apply.
        </div>
      )}
      {hasDiff && isBestEffort(patch.unified_diff) && (
        <div className="rounded-md border border-info/30 bg-info/10 px-3 py-2 text-xs text-info">
          This is a best-effort hint patch. Approving applies the annotation only; the source code is not rewritten automatically.
        </div>
      )}
      <div className="space-y-2">
        <Button className="w-full" variant="default"
          disabled={!hasDiff || status !== "pending_review" || decide.isPending}
          onClick={() => decide.mutate("approved")}>
          <ShieldCheck className="h-4 w-4" />Approve
        </Button>
        <Button className="w-full" variant="outline"
          disabled={status !== "pending_review" || decide.isPending}
          onClick={() => decide.mutate("rejected")}>
          <ShieldAlert className="h-4 w-4" />Reject
        </Button>
      </div>

      <Button className="w-full"
        disabled={!hasDiff || status !== "approved" || apply.isPending}
        onClick={() => { setApplyErr(null); apply.mutate(); }}>
        {apply.isPending
          ? <Loader2 className="h-4 w-4 animate-spin" />
          : isApplied
            ? <><CheckCircle2 className="h-4 w-4" />Applied</>
            : <><Wand2 className="h-4 w-4" />Apply patch</>}
      </Button>

      <Button className="w-full" variant="ghost" size="sm"
        disabled={!hasDiff || (status !== "approved" && !isApplied)}
        onClick={() => setPrOpen(true)}>
        <GitPullRequest className="h-4 w-4" />Open pull request instead
      </Button>

      {applyErr && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">{applyErr}</div>
      )}

      <p className="text-[11px] text-muted-foreground">
        {!hasDiff
          ? `Pipeline abstained at stage ${patch.stage_reached}. Try a different file or rule.`
          : isApplied
            ? "Patch written to disk. A .irsam.bak backup of the original file is kept alongside."
            : status === "approved"
              ? "Click Apply patch to write the fix directly to the source file on disk."
              : status === "pending_review"
                ? "Review the diff on the left, then approve to enable applying the patch."
                : `Current status: ${status}.`}
      </p>

      {prOpen && (
        <OpenPRDialog patch={patch} onClose={() => setPrOpen(false)}
          onCreated={() => { setPrOpen(false); qc.invalidateQueries({ queryKey: ["finding-patches", findingId] }); }} />
      )}
    </div>
  );
}

function OpenPRDialog({
  patch, onClose, onCreated,
}: { patch: PatchProposal; onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    repo_owner: "", repo_name: "", base_branch: "main", token: "",
    branch_prefix: "irsam/fix",
  });
  const [err, setErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => api.post(`/patches/${patch.id}/pull-request`, form),
    onSuccess: onCreated,
    onError: (e: any) => setErr(e?.payload?.detail ?? "Could not open PR"),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/70 backdrop-blur-sm" onClick={onClose}>
      <div className="glass w-full max-w-md rounded-2xl p-6" onClick={(e) => e.stopPropagation()}>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-lg font-semibold"><Github className="h-4 w-4" />Open GitHub PR</h2>
          <Button size="icon" variant="ghost" onClick={onClose}><X className="h-4 w-4" /></Button>
        </div>
        <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); setErr(null); create.mutate(); }}>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <Label>Owner</Label>
              <Input required className="mt-1 font-mono" value={form.repo_owner}
                onChange={(e) => setForm(f => ({ ...f, repo_owner: e.target.value }))} placeholder="acme" />
            </div>
            <div>
              <Label>Repo</Label>
              <Input required className="mt-1 font-mono" value={form.repo_name}
                onChange={(e) => setForm(f => ({ ...f, repo_name: e.target.value }))} placeholder="payments" />
            </div>
          </div>
          <div>
            <Label>Base branch</Label>
            <Input className="mt-1 font-mono" value={form.base_branch}
              onChange={(e) => setForm(f => ({ ...f, base_branch: e.target.value }))} />
          </div>
          <div>
            <Label>PAT (repo scope)</Label>
            <Input required type="password" className="mt-1 font-mono" value={form.token}
              onChange={(e) => setForm(f => ({ ...f, token: e.target.value }))}
              placeholder="ghp_••••••••••••••••" />
            <p className="mt-1 text-[11px] text-muted-foreground">
              Token is sent once and not stored on the server.
            </p>
          </div>
          {err && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">{err}</div>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <><GitPullRequest className="h-4 w-4" />Open PR</>}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

function StateMenu({
  current, onChange, disabled,
}: { current: string; onChange: (s: "open" | "dismissed" | "wont_fix") => void; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <Button variant="outline" size="sm" disabled={disabled} onClick={() => setOpen(o => !o)}>
        Change state <ChevronDown className="h-3 w-3" />
      </Button>
      {open && (
        <div className={cn(
          "absolute right-0 z-40 mt-2 w-40 overflow-hidden rounded-md border border-border bg-card/95 backdrop-blur-md shadow-xl",
        )}>
          {(["open", "dismissed", "wont_fix"] as const).map(s => (
            <button key={s}
              className={cn(
                "block w-full px-3 py-2 text-left text-sm hover:bg-muted/50",
                s === current && "text-primary",
              )}
              onClick={() => { setOpen(false); onChange(s); }}>
              {s}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// -- diff helpers ---------------------------------------------------------

function splitUnifiedDiff(diff: string): { before: string; after: string } {
  const before: string[] = [];
  const after:  string[] = [];
  let inHunk = false;
  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith("@@")) { inHunk = true; continue; }
    if (!inHunk) continue;
    if (line.startsWith("---") || line.startsWith("+++") || line.startsWith("diff ")) continue;
    if (line.startsWith("-"))      before.push(line.slice(1));
    else if (line.startsWith("+")) after.push(line.slice(1));
    else if (line.startsWith(" ")) { before.push(line.slice(1)); after.push(line.slice(1)); }
  }
  return { before: before.join("\n"), after: after.join("\n") };
}

function guessLanguage(file: string): string {
  const ext = file.split(".").pop()?.toLowerCase();
  switch (ext) {
    case "java": return "java";
    case "py":   return "python";
    case "xml":  return "xml";
    default:     return "plaintext";
  }
}

// -- "What did IR-SAM do?" proof panel ------------------------------------

const PROOF_TONE: Record<string, "info" | "warn" | "success" | "danger" | "violet" | "neutral"> = {
  proven: "success",
  axiomatized: "violet",
  validated_only: "info",
  best_effort: "warn",
  unverified: "danger",
};

const PROOF_BLURB: Record<string, string> = {
  proven: "Patch validated by all gates AND the binder's proof obligation is discharged by an active Lean theorem.",
  axiomatized: "Patch validated; proof obligation references a Lean axiom (assumption made explicit in §A).",
  validated_only: "Patch validated empirically (all five gates green); no formal proof obligation declared for this binder.",
  best_effort: "Pipeline could not produce a sound rewrite. The diff inserts a remediation hint at the sink for human review.",
  unverified: "Patch emitted but one or more gates failed or were soft-failed.",
};

function ProofPanel({ patch }: { patch: PatchProposal }) {
  const plan = patch.plan ?? null;
  const gates = patch.gate_report?.gates ?? [];
  const proofStatus = plan?.proof_status ?? "unverified";
  const binders = plan?.binders_used ?? [];
  const template = plan?.prepared_template ?? null;
  const claim = plan?.safety_claim ?? "";
  const reason = plan?.abstention_reason ?? null;

  // Stable canonical gate order. Worker may emit a subset; missing gates are
  // shown as "n/a" so the user always sees the full validator surface.
  const CANONICAL = [
    "G1_syntactic_equivalence",
    "G2_semantic_preservation",
    "G3_residual_cwe_scan",
    "G4_behavioural_tests",
    "G5_patch_minimality",
  ] as const;
  const gateMap = new Map(gates.map((g) => [g.name, g]));

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">What did IR-SAM do?</CardTitle>
          <Badge tone={PROOF_TONE[proofStatus] ?? "neutral"}>{proofStatus}</Badge>
        </div>
        <CardDescription>
          {PROOF_BLURB[proofStatus] ?? "No proof metadata available."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {reason && (
          <div className="rounded-md border border-warning/30 bg-warning/10 px-3 py-2 text-xs text-warning">
            <span className="font-medium">Abstention:</span>{" "}
            <span className="font-mono">{reason}</span>
          </div>
        )}

        <div className="grid gap-4 md:grid-cols-2">
          {/* SIG / binder column */}
          <div className="space-y-3">
            <div className="text-xs uppercase tracking-widest text-muted-foreground">
              Sink Intent Graph · φ binder
            </div>
            {binders.length === 0 ? (
              <p className="text-xs text-muted-foreground">No binder catalog was activated for this finding.</p>
            ) : (
              <ul className="flex flex-wrap gap-1.5">
                {binders.map((b) => (
                  <li key={b}>
                    <span className="rounded-full border border-secondary/30 bg-secondary/10 px-2 py-0.5 text-[11px] font-mono text-secondary-foreground">
                      {b}
                    </span>
                  </li>
                ))}
              </ul>
            )}

            <div className="text-xs uppercase tracking-widest text-muted-foreground pt-2">
              Prepared template
            </div>
            {template ? (
              <pre className="overflow-x-auto rounded-md border border-border bg-background/60 p-3 text-[11px] font-mono text-foreground/90 whitespace-pre-wrap">
                {template}
              </pre>
            ) : (
              <p className="text-xs text-muted-foreground">No prepared template (pipeline abstained before φ).</p>
            )}

            {claim && (
              <p className="text-[11px] text-muted-foreground italic">{claim}</p>
            )}
          </div>

          {/* Five gates column */}
          <div className="space-y-2">
            <div className="text-xs uppercase tracking-widest text-muted-foreground">
              Validator · 5 gates
            </div>
            <ul className="space-y-1.5">
              {CANONICAL.map((name) => {
                const g = gateMap.get(name);
                const passed = g?.passed;
                const tone =
                  g === undefined ? "neutral" :
                  passed ? "success" : "danger";
                const label = name.replace(/^G\d_/, "").replace(/_/g, " ");
                return (
                  <li
                    key={name}
                    className="flex items-center justify-between rounded-md border border-border bg-card/40 px-3 py-2 text-xs"
                  >
                    <span>
                      <span className="font-mono text-muted-foreground">{name.slice(0, 2)}</span>
                      {" · "}
                      <span>{label}</span>
                    </span>
                    <Badge tone={tone as any}>
                      {g === undefined ? "n/a" : passed ? "pass" : "fail"}
                    </Badge>
                  </li>
                );
              })}
            </ul>
            {gates.some((g) => !g.passed && g.detail) && (
              <details className="mt-2 text-xs text-muted-foreground">
                <summary className="cursor-pointer hover:text-foreground">Show failure details</summary>
                <ul className="mt-2 space-y-1">
                  {gates.filter((g) => !g.passed && g.detail).map((g) => (
                    <li key={g.name} className="font-mono text-[11px]">
                      <span className="text-destructive">{g.name}:</span> {g.detail}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
