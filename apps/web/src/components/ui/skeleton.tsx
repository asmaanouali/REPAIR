import * as React from "react";
import { cn } from "@/lib/utils";

export function Skeleton({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-md bg-muted/60 animate-pulse",
        className,
      )}
      {...p}
    />
  );
}
