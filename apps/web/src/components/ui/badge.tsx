import * as React from "react";
import { cn } from "@/lib/utils";

type Tone = "neutral" | "info" | "success" | "warn" | "danger" | "violet";

const TONE: Record<Tone, string> = {
  neutral: "bg-muted text-muted-foreground border-border",
  info:    "bg-primary/15 text-primary border-primary/30",
  success: "bg-success/15 text-success border-success/30",
  warn:    "bg-warning/15 text-warning border-warning/30",
  danger:  "bg-destructive/15 text-destructive border-destructive/30",
  violet:  "bg-secondary/15 text-secondary border-secondary/30",
};

export function Badge({
  className,
  tone = "neutral",
  ...p
}: React.HTMLAttributes<HTMLSpanElement> & { tone?: Tone }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium",
        TONE[tone],
        className,
      )}
      {...p}
    />
  );
}

export function StatusDot({ tone = "neutral" }: { tone?: Tone }) {
  const color =
    tone === "success" ? "bg-success" :
    tone === "warn"    ? "bg-warning" :
    tone === "danger"  ? "bg-destructive" :
    tone === "info"    ? "bg-primary" :
    tone === "violet"  ? "bg-secondary" :
                         "bg-muted-foreground";
  return (
    <span className={cn("inline-block h-2 w-2 rounded-full", color)}>
      <span className={cn("block h-full w-full rounded-full animate-ping opacity-60", color)} />
    </span>
  );
}
