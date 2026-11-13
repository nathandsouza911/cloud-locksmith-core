"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  AlertTriangle,
  BookOpen,
  Building2,
  ChevronRight,
  FileBarChart2,
  BarChart3,
  HelpCircle,
  LayoutDashboard,
  Library,
  LogOut,
  Menu,
  Moon,
  Plus,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Sun,
  X,
  Zap,
  Activity,
  Users,
  Receipt,
  MessageSquare,
  Layers,
  ClipboardList,
  KeyRound,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui";
import { PreviewModeBanner } from "@/components/ui/PreviewModeBanner";
import { useBreakGlassEvents } from "@/lib/api/hooks";
import { useAuth } from "@/lib/auth-context";
import { startMicrosoftOAuth } from "@/lib/auth";
import { loginPathKeepingConnectError } from "@/lib/connect-errors";

// Sprint 1 — navigation is organised by WORK, not by data category
// (Product Bible §14). "My Work" leads; the posture Dashboard is demoted under
// Fleet rather than removed, and every previously-reachable screen stays
// reachable.
const NAV_GROUPS = [
  {
    label: "Work",
    items: [
      { href: "/work", label: "My Work", icon: ClipboardList },
      { href: "/work/oauth-review", label: "OAuth Review", icon: KeyRound },
      { href: "/workflows", label: "Workflow Library", icon: Library },
      { href: "/risk-feed", label: "Risk Feed", icon: Zap },
      { href: "/campaigns", label: "Campaigns", icon: Layers, mspOnly: true },
      { href: "/operations/live", label: "Operations", icon: Activity, mspOnly: true },
    ],
  },
  {
    label: "Clients",
    items: [
      { href: "/tenants", label: "Clients", icon: Building2 },
      { href: "/users", label: "Users", icon: Users },
      { href: "/remediation-timeline", label: "Remediation Timeline", icon: Activity },
      { href: "/remediation-history", label: "Remediation History", icon: Activity },
    ],
  },
  {
    label: "Reports",
    items: [
      { href: "/reports", label: "Reports", icon: FileBarChart2 },
      { href: "/fleet-report", label: "Fleet Report", icon: BarChart3, mspOnly: true },
      { href: "/compliance", label: "Compliance", icon: ShieldCheck },
      { href: "/cost-optimization", label: "Cost Optimization", icon: Receipt },
    ],
  },
  {
    label: "Fleet",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/dashboard/attack-paths", label: "Attack Paths", icon: AlertTriangle },
      { href: "/controls", label: "Security Controls", icon: ShieldCheck },
      { href: "/baselines", label: "Security Baselines", icon: BookOpen },
    ],
  },
  {
    label: "System",
    items: [
      { href: "/help", label: "Help", icon: HelpCircle },
      { href: "/support", label: "Support & Feedback", icon: MessageSquare },
      { href: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const {
    loading,
    authed,
    user,
    tenantId,
    tenants,
    selectedTenant,
    requiresTenantSelection,
    isSmb,
    isPreviewMode,
    setActiveTenantId,
    logout,
  } = useAuth();
  const breakGlassEventsQuery = useBreakGlassEvents(tenantId);
  const [dark, setDark] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  useEffect(() => {
    if (!loading && !authed) {
      // Keep a sign-in failure code (e.g. a refused Microsoft callback) so /login can explain it.
      router.replace(loginPathKeepingConnectError(window.location.search));
    }
  }, [loading, authed, router]);

  const initials = useMemo(() => (user?.email ?? "AD").slice(0, 2).toUpperCase(), [user?.email]);
  const latestBreakGlassEvent = breakGlassEventsQuery.data?.[0] ?? null;
  const navGroups = useMemo(
    () =>
      NAV_GROUPS.map((group) => ({
        ...group,
        items: group.items.filter((item) => {
          if (item.href === "/tenants" && isSmb) return false;
          if ((item as { mspOnly?: boolean }).mspOnly && isSmb) return false;
          return true;
        }),
      })).filter((group) => group.items.length > 0),
    [isSmb],
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <Shield size={20} className="text-white" />
          </div>
          <div className="w-5 h-5 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        </div>
      </div>
    );
  }

  if (!authed) return null;

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans flex">
      <aside
        className={`
          fixed inset-y-0 left-0 z-40 w-64 flex flex-col
          bg-gray-900/98 backdrop-blur border-r border-gray-800
          transition-transform duration-200
          ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}
          lg:relative lg:translate-x-0 lg:flex
        `}
      >
        <div className="flex items-center gap-2.5 px-5 py-5 border-b border-gray-800">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Shield size={16} className="text-white" />
          </div>
          <div>
            <p className="text-sm font-bold tracking-tight text-white">Cloud Locksmith</p>
            <p className="text-[10px] text-gray-400 tracking-wider uppercase">MSP Security</p>
          </div>
        </div>

        {!isSmb ? (
          <div className="px-4 py-4 border-b border-gray-800 space-y-3">
            <div>
              <p className="text-[10px] font-semibold tracking-widest text-gray-500 uppercase mb-2">
                Active Tenant
              </p>
              <select
                value={tenantId ?? ""}
                onChange={(event) => setActiveTenantId(event.target.value || null)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-sm text-gray-200 outline-none focus:border-cyan-500 transition-colors"
              >
                <option value="">{tenants.length === 0 ? "No tenants connected" : "Select tenant"}</option>
                {tenants.map((tenant) => (
                  <option key={tenant.tenant_id} value={tenant.tenant_id}>
                    {tenant.tenant_name} ({tenant.role})
                  </option>
                ))}
              </select>
            </div>
            <Button
              variant="primary"
              size="sm"
              className="w-full justify-center"
              onClick={() => {
                startMicrosoftOAuth("msp_connect");
              }}
            >
              <Plus size={13} />
              Add Tenant
            </Button>
          </div>
        ) : null}

        <nav className="flex-1 px-3 py-4 overflow-y-auto space-y-5">
          {navGroups.map((group) => (
            <div key={group.label} data-nav-group={group.label}>
              <p
                data-testid="nav-group-label"
                className="px-2 pb-2 text-[10px] font-semibold tracking-widest text-gray-500 uppercase"
              >
                {group.label}
              </p>
              <div className="space-y-0.5">
                {group.items.map(({ href, label, icon: Icon }) => {
                  const active = pathname === href || pathname.startsWith(`${href}/`);
                  return (
                    <Link
                      key={href}
                      href={href}
                      onClick={() => setSidebarOpen(false)}
                      className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${
                        active
                          ? "bg-cyan-500/15 text-cyan-400 font-semibold"
                          : "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
                      }`}
                    >
                      <Icon size={15} className={active ? "text-cyan-400" : ""} />
                      {label}
                      {active && <ChevronRight size={12} className="ml-auto text-cyan-500 opacity-70" />}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="px-4 py-2 border-t border-gray-800/50">
          <div className="flex items-center gap-2 px-3 py-2 bg-gray-800/50 rounded-lg">
            <div
              className={`w-1.5 h-1.5 rounded-full shrink-0 ${tenantId ? "bg-green-400" : "bg-yellow-400"}`}
            />
            <div className="min-w-0">
              <p className="text-[11px] text-gray-300 truncate">
                {selectedTenant?.tenant_name ??
                  (tenants.length === 0 ? "No tenants connected" : "Tenant selection required")}
              </p>
              <p className="text-[10px] text-gray-500 font-mono truncate">
                {tenantId ?? "Set X-Tenant-ID by selecting a tenant"}
              </p>
            </div>
          </div>
        </div>

        <div className="px-4 py-4 border-t border-gray-800 space-y-2">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center text-xs font-bold text-white shrink-0">
              {initials}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-gray-200 truncate">{user?.email ?? "Admin"}</p>
              <p className="text-[10px] text-gray-500">
                {isSmb
                  ? "Tenant Owner"
                  : requiresTenantSelection
                    ? "Select a tenant to continue"
                    : "MSP Administrator"}
              </p>
            </div>
            <button
              onClick={logout}
              className="p-1.5 rounded-md text-gray-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
              title="Sign out"
            >
              <LogOut size={14} />
            </button>
          </div>
        </div>
      </aside>

      {sidebarOpen && (
        <div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      <div className="flex-1 flex flex-col min-w-0">
        <header className="sticky top-0 z-20 h-14 flex items-center gap-4 px-4 lg:px-6 bg-gray-950/80 backdrop-blur border-b border-gray-800">
          <button
            onClick={() => setSidebarOpen((value) => !value)}
            className="lg:hidden p-1.5 rounded-md text-gray-400 hover:text-gray-200 hover:bg-gray-800 transition-colors"
          >
            {sidebarOpen ? <X size={18} /> : <Menu size={18} />}
          </button>

          <div className="hidden sm:flex items-center gap-2 flex-1 max-w-sm bg-gray-800/60 border border-gray-700 rounded-lg px-3 py-1.5">
            <Search size={14} className="text-gray-400" />
            <input
              className="flex-1 bg-transparent text-sm text-gray-300 placeholder:text-gray-500 outline-none"
              placeholder="Search tenants, controls..."
            />
          </div>

          <div className="ml-auto flex items-center gap-2">
            {requiresTenantSelection ? (
              <span className="hidden md:inline-flex text-xs text-yellow-300 bg-yellow-500/10 border border-yellow-500/20 px-3 py-1.5 rounded-lg">
                Select a tenant
              </span>
            ) : null}
            <button
              onClick={() => setDark((value) => !value)}
              className="p-1.5 rounded-md text-gray-400 hover:text-gray-200 hover:bg-gray-800 transition-colors"
            >
              {dark ? <Sun size={16} /> : <Moon size={16} />}
            </button>
          </div>
        </header>

        {isPreviewMode && <PreviewModeBanner />}

        <main className="flex-1 overflow-auto px-4 lg:px-6 py-6">
          {tenantId && latestBreakGlassEvent ? (
            <div className="mb-6 rounded-2xl border border-red-500/40 bg-[linear-gradient(135deg,rgba(127,29,29,0.92),rgba(17,24,39,0.96))] px-5 py-4 shadow-lg shadow-red-950/40">
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="text-sm font-semibold text-red-100">
                    Break-glass account used. Immediate review required.
                  </p>
                  <p className="mt-1 text-xs text-red-100/80">
                    {latestBreakGlassEvent.user_principal_name ?? latestBreakGlassEvent.user_id}
                    {latestBreakGlassEvent.timestamp
                      ? ` signed in at ${new Date(latestBreakGlassEvent.timestamp).toLocaleString()}`
                      : " activity detected"}
                    {latestBreakGlassEvent.location ? ` from ${latestBreakGlassEvent.location}` : ""}.
                  </p>
                </div>
                <div className="inline-flex items-center gap-2 self-start rounded-full border border-red-200/20 bg-black/20 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-red-100">
                  <AlertTriangle size={13} />
                  Critical
                </div>
              </div>
            </div>
          ) : null}
          {children}
        </main>

        <footer className="shrink-0 border-t border-gray-800 px-4 lg:px-6 py-3">
          <div className="flex flex-wrap gap-4 text-xs text-gray-500">
            <span>Cloud Locksmith Core · AGPL-3.0</span>
          </div>
        </footer>
      </div>
    </div>
  );
}
