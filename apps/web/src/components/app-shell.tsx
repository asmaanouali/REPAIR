"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  ShieldCheck, LayoutDashboard, FolderGit2, Wand2, Settings,
  LogOut, Search, Bell, ChevronRight,
} from "lucide-react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { api, type User } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/projects",  label: "Projects",  icon: FolderGit2 },
  { href: "/quickfix",  label: "Quickfix",  icon: Wand2 },
  { href: "/settings",  label: "Settings",  icon: Settings },
];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: () => api.get<User>("/auth/me"),
    retry: false,
  });
  const logout = useMutation({
    mutationFn: () => api.post("/auth/logout"),
    onSuccess: () => router.replace("/login"),
  });

  return (
    <div className="flex min-h-screen bg-background">
      <aside className="hidden w-64 shrink-0 border-r border-border bg-card lg:flex lg:flex-col">
        <div className="flex h-16 items-center gap-2 border-b border-border px-6">
          <ShieldCheck className="h-5 w-5 text-primary" />
          <span className="text-sm font-semibold tracking-tight">IR-SAM</span>
          <span className="ml-auto rounded border border-border/70 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">v1</span>
        </div>
        <nav className="flex-1 space-y-1 p-3">
          {NAV.map((n) => {
            const active = pathname === n.href || pathname.startsWith(n.href + "/");
            const Icon = n.icon;
            return (
              <Link key={n.href} href={n.href}
                className={cn(
                  "group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-muted/40 hover:text-foreground",
                )}>
                <Icon className="h-4 w-4" />
                <span>{n.label}</span>
                <ChevronRight className={cn(
                  "ml-auto h-3 w-3 opacity-0 transition-opacity",
                  active && "opacity-100",
                )} />
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-border p-3">
          <div className="flex items-center gap-3 rounded-md px-2 py-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground">
              {me?.email?.[0]?.toUpperCase() ?? "?"}
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-xs font-medium">{me?.email ?? "—"}</div>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{me?.role ?? "owner"}</div>
            </div>
            <Button size="icon" variant="ghost" title="Sign out"
              onClick={() => logout.mutate()}>
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border/80 bg-background/70 px-6 backdrop-blur">
          <div className="relative max-w-md flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              placeholder="Search projects, findings, CWEs…"
              className="h-9 w-full rounded-md border border-input bg-background/40 pl-9 pr-3 text-sm outline-none ring-offset-background placeholder:text-muted-foreground/70 focus-visible:ring-2 focus-visible:ring-ring"
            />
          </div>
          <Button size="icon" variant="ghost" title="Notifications">
            <Bell className="h-4 w-4" />
          </Button>
        </header>
        <main className="flex-1 px-6 py-8">{children}</main>
      </div>
    </div>
  );
}
