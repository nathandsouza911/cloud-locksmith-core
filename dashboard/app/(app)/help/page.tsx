"use client";

/**
 * Help & Documentation — /help.
 *
 * A single reference page for the whole app, not per-section subpages: one
 * URL, browser find (Ctrl+F) works across everything, and a support agent
 * can link a client straight to `#risk-feed`. The table of contents and the
 * search box both read from SECTIONS below, so a title can't drift out of
 * sync between "what's listed" and "what's on the page."
 *
 * Content is grounded in what each screen actually does today — including
 * the couple of things that are visibly present but not yet wired (call
 * those out rather than let a user click and wonder why nothing happened).
 */

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  Activity,
  BarChart3,
  BookOpen,
  Building2,
  ClipboardList,
  FileBarChart2,
  KeyRound,
  Layers,
  LayoutDashboard,
  Library,
  MessageSquare,
  Receipt,
  Search,
  Settings,
  ShieldCheck,
  Users,
  Zap,
  type LucideIcon,
} from "lucide-react";

import { Card, PageHeader } from "@/components/ui";

// ─── Content model ──────────────────────────────────────────────────────────

interface HelpSection {
  id: string;
  title: string;
  icon: LucideIcon;
  path?: string; // sidebar destination, when this section is a real page
  audience?: string; // e.g. "MSP mode only"
  purpose: string;
  actions?: string[];
  note?: string;
}

interface HelpGroup {
  label: string;
  intro?: string;
  sections: HelpSection[];
}

const GROUPS: HelpGroup[] = [
  {
    label: "Concepts",
    intro:
      "Read this first if you're new — everything else on this page is a reference for a screen you're already looking at.",
    sections: [
      {
        id: "concept-queue",
        title: "A queue, not a score",
        icon: ClipboardList,
        purpose:
          "Cloud Locksmith is organized around work, not a security score. Instead of a dashboard telling you how secure a tenant is, My Work tells you what needs doing today — a prioritized list you clear, the same way you'd clear a ticket queue.",
      },
      {
        id: "concept-lifecycle",
        title: "The review lifecycle",
        icon: Activity,
        purpose:
          "Every recurring workflow (Identity Hygiene, OAuth Review, Admin Access Review, and the rest) follows the same four stages.",
        actions: [
          "Discover — opening a workflow finds every outstanding item automatically; you never hunt for it.",
          "Review — each item shows a risk level and a plain-English reason, not just a control ID.",
          "Remediate — Keep / Ignore / Escalate just record your decision. The fix action (labeled Disable, Revoke, or Fix now depending on the workflow) simulates the change first, then requires you to type CONFIRM before it actually executes.",
          "Verify — fixed items are periodically re-checked; if one gets silently reverted, it's flagged again rather than assumed to still be fine.",
        ],
      },
      {
        id: "concept-decisions",
        title: "What each decision button does",
        icon: KeyRound,
        purpose: "The same four decisions appear across every review screen.",
        actions: [
          "Keep — sanctioned as-is. Recorded, nothing else happens.",
          "Ignore — deliberately taking no action. Recorded, nothing else happens.",
          "Escalate — flags it as needing someone else's judgment. Recorded, nothing else happens — there's no ticket or notification behind it yet, so tell the person directly for now.",
          "Disable / Revoke / Fix now — the only decision that changes anything live. Click it, review the simulated impact, type CONFIRM, then it executes for real against Microsoft 365 through the same engine every remediation uses, and it's rollback-capable.",
        ],
      },
      {
        id: "concept-tenants",
        title: "Clients, tenants, and MSP mode",
        icon: Building2,
        purpose:
          "A \"tenant\" is one client's Microsoft 365 environment. If your account manages more than one client, you're in MSP mode and see a tenant switcher plus MSP-only sections (Campaigns, Operations, Clients, Fleet Report). A single-business account (SMB mode) sees only its own tenant and those sections are hidden.",
      },
    ],
  },
  {
    label: "Work",
    sections: [
      {
        id: "my-work",
        title: "My Work",
        icon: ClipboardList,
        path: "/work",
        purpose:
          "The landing screen — a prioritized list of everything outstanding for the selected client, pulled across every workflow at once.",
        actions: ["Click Review on any card to open that workflow's review screen."],
      },
      {
        id: "oauth-review",
        title: "OAuth Review",
        icon: KeyRound,
        path: "/work/oauth-review",
        purpose:
          "Reviews newly consented third-party applications — which ones can read mail, act on a mailbox, or hold tenant-wide access. Its own sidebar entry because it's the platform's flagship recurring workflow.",
        actions: [
          "Same decision buttons as every review screen: Keep, Revoke, Escalate, Ignore, then Complete review.",
        ],
      },
      {
        id: "workflow-library",
        title: "Workflow Library",
        icon: Library,
        path: "/workflows",
        purpose:
          "A read-only catalog of every workflow type the platform can run — not a queue, a reference.",
        actions: ["Click View supported controls on any card to see exactly what it checks."],
      },
      {
        id: "risk-feed",
        title: "Risk Feed",
        icon: Zap,
        path: "/risk-feed",
        purpose:
          "A cross-tenant, real-time list of open findings, for triaging across clients rather than one workflow at a time.",
        actions: [
          "Filter by tenant and severity.",
          "Approve a finding, or Fix Now / Execute / Retry to remediate it directly.",
          "Simulate Fix to preview a Conditional Access change before applying it.",
          "Mark as Authorized to acknowledge expected break-glass account usage.",
          "Review Account to jump into offboarding for an unused admin account.",
        ],
        note: "Some fixes require an Entra ID P1/P2 license.",
      },
      {
        id: "campaigns",
        title: "Campaigns",
        icon: Layers,
        path: "/campaigns",
        audience: "MSP mode only",
        purpose:
          "Bulk remediation across many client tenants at once, for a small, deliberately conservative set of low-risk controls.",
        actions: [
          "New Campaign — choose controls and target tenants, optionally toggle Dry Run first.",
          "On a campaign: Approve, Execute (typed confirmation), Rollback, or Export CSV / Export PDF.",
        ],
        note: "Only three controls are offered here on purpose: unused accounts, open guest invitations, and user consent policy — the ones safe enough to touch across a whole fleet at once.",
      },
      {
        id: "operations",
        title: "Operations",
        icon: Activity,
        path: "/operations/live",
        audience: "MSP mode only",
        purpose:
          "A live, auto-refreshing view of campaign execution, scheduled jobs, and drift across every client — for watching, not clicking.",
      },
    ],
  },
  {
    label: "Clients",
    sections: [
      {
        id: "clients",
        title: "Clients",
        icon: Building2,
        path: "/tenants",
        audience: "MSP mode only",
        purpose: "Manage the list of connected client tenants.",
        actions: [
          "Add Tenant to start Microsoft admin-consent onboarding for a new client.",
          "Scan All Tenants, or Scan Now on one tenant.",
          "Switch to change which tenant the rest of the app is scoped to.",
          "Reconnect if a client's connection needs re-authorizing.",
          "Delete — type DELETE to confirm. Only available to account owners/admins.",
        ],
      },
      {
        id: "users",
        title: "Users",
        icon: Users,
        path: "/users",
        purpose:
          "The selected tenant's user roster, with risk indicators and the entry point into offboarding.",
        actions: [
          "Offboard User to start a guided, step-by-step offboarding session (you'll get an extra warning if the account is a Global Administrator).",
          "Rollback Offboarding on a completed offboard.",
        ],
      },
      {
        id: "remediation-timeline",
        title: "Remediation Timeline",
        icon: Activity,
        path: "/remediation-timeline",
        purpose:
          "A single chronological feed mixing audit events and remediation actions for one tenant, plus a 14-day posture trend.",
        actions: ["Filter by event kind or actor.", "Refresh to pull the latest."],
        note: "The Export button is visible but not wired up yet — nothing happens if you click it.",
      },
      {
        id: "remediation-history",
        title: "Remediation History",
        icon: Activity,
        path: "/remediation-history",
        purpose: "A record of past successful remediations.",
        actions: ["Rollback on any row where it's still available."],
      },
    ],
  },
  {
    label: "Reports",
    sections: [
      {
        id: "reports",
        title: "Reports",
        icon: FileBarChart2,
        path: "/reports",
        purpose:
          "Generate and download the client-facing evidence reports the platform produces automatically from completed work.",
        actions: [
          "Regenerate Report / Evidence Report PDF to build a fresh evidence report.",
          "Cyber Insurance PDF for the underwriting-oriented evidence report.",
          "Verify Integrity to confirm an archived report hasn't been altered since it was generated.",
          "Download or View on any past report.",
        ],
      },
      {
        id: "fleet-report",
        title: "Fleet Report",
        icon: BarChart3,
        path: "/fleet-report",
        audience: "MSP mode only",
        purpose: "Ranks every client tenant by posture score and trend, in one list.",
        actions: ["Click a tenant to open it in Clients."],
      },
      {
        id: "compliance",
        title: "Compliance",
        icon: ShieldCheck,
        path: "/compliance",
        purpose:
          "Browse how the controls Cloud Locksmith checks map to named frameworks (CIS Microsoft 365 Benchmark, CISA SCuBA, NIST CSF).",
        actions: [
          "Click a framework card to filter to just its controls.",
          "Filter by status, or search by name.",
          "Click a control to open its detail — from there, View in Risk Feed jumps straight to fixing it.",
        ],
      },
      {
        id: "cost-optimization",
        title: "Cost Optimization",
        icon: Receipt,
        path: "/cost-optimization",
        purpose:
          "Surfaces Microsoft 365 license waste for the selected tenant — inactive accounts, unused seats, premium overspend.",
        actions: ["Refresh Scan to re-run the license scan.", "Download Report for a shareable summary."],
      },
    ],
  },
  {
    label: "Fleet",
    sections: [
      {
        id: "dashboard",
        title: "Dashboard",
        icon: LayoutDashboard,
        path: "/dashboard",
        purpose: "A posture overview — fleet-wide for MSP accounts, single-tenant for SMB accounts.",
        actions: ["Add Tenant.", "Refresh.", "Fix or Review on any listed finding."],
      },
      {
        id: "attack-paths",
        title: "Attack Paths",
        icon: AlertTriangle,
        path: "/dashboard/attack-paths",
        purpose:
          "Shows breach scenarios that exist right now because a specific combination of failed controls lines up in the selected tenant.",
        actions: ["Fix this path to open the remediation for that scenario."],
      },
      {
        id: "security-controls",
        title: "Security Controls",
        icon: ShieldCheck,
        path: "/controls",
        purpose:
          "A fixed catalog of identity and Conditional Access controls you can enforce directly for the selected tenant.",
        actions: ["Click a control's fix button, then confirm in the Review & Fix dialog."],
      },
      {
        id: "security-baselines",
        title: "Security Baselines",
        icon: BookOpen,
        path: "/baselines",
        purpose:
          "Define a reusable set of controls as a named baseline, then apply it as the desired state across tenants.",
        actions: ["Select controls, Save Baseline Template, then Apply Baseline (or Apply on a saved one)."],
        note: "Applying a baseline sets the desired state — it doesn't execute anything by itself. Remediation still happens through the normal review or Risk Feed flow.",
      },
    ],
  },
  {
    label: "System",
    sections: [
      {
        id: "support",
        title: "Support & Feedback",
        icon: MessageSquare,
        path: "/support",
        purpose: "Submit a ticket and see your own past requests.",
        actions: ["Choose a type and severity, fill in a subject and description, then Submit."],
        note: "Attachments aren't supported yet — reply to the confirmation email if you need to send a file.",
      },
      {
        id: "settings",
        title: "Settings",
        icon: Settings,
        path: "/settings",
        purpose:
          "Account-level administration: your Microsoft connection, a fix simulation, and account deletion.",
        actions: [
          "Re-authorize Microsoft if your connection needs refreshing.",
          "Sign Out.",
          "Delete Account (single-business accounts only) — type DELETE to confirm.",
        ],
      },
    ],
  },
];

const ALL_SECTIONS: HelpSection[] = GROUPS.flatMap((g) => g.sections);

// ─── Page ───────────────────────────────────────────────────────────────────

export default function HelpPage() {
  const [query, setQuery] = useState("");

  const matchedIds = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return null;
    const ids = new Set<string>();
    for (const section of ALL_SECTIONS) {
      const haystack = [section.title, section.purpose, ...(section.actions ?? [])].join(" ").toLowerCase();
      if (haystack.includes(q)) ids.add(section.id);
    }
    return ids;
  }, [query]);

  return (
    <div>
      <PageHeader
        title="Help & Documentation"
        subtitle="What every screen in Cloud Locksmith does, and how to use it"
      />

      <div className="mb-6 relative max-w-md">
        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search help topics…"
          className="w-full bg-gray-900/70 border border-gray-800 rounded-lg pl-9 pr-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 outline-none focus:border-cyan-600 transition-colors"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-8 items-start">
        {/* Table of contents */}
        <nav className="lg:sticky lg:top-6 space-y-5">
          {GROUPS.map((group) => (
            <div key={group.label}>
              <p className="px-1 pb-2 text-[10px] font-semibold tracking-widest text-gray-500 uppercase">
                {group.label}
              </p>
              <div className="space-y-0.5">
                {group.sections.map((section) => {
                  const dimmed = matchedIds !== null && !matchedIds.has(section.id);
                  return (
                    <a
                      key={section.id}
                      href={`#${section.id}`}
                      className={`flex items-center gap-2 px-2 py-1.5 rounded-md text-xs transition-colors ${
                        dimmed ? "text-gray-700" : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/60"
                      }`}
                    >
                      <section.icon size={13} className="shrink-0" />
                      <span className="truncate">{section.title}</span>
                    </a>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Content */}
        <div className="space-y-10 min-w-0">
          {GROUPS.map((group) => {
            const visibleSections =
              matchedIds === null ? group.sections : group.sections.filter((s) => matchedIds.has(s.id));
            if (visibleSections.length === 0) return null;

            return (
              <section key={group.label}>
                <p className="text-[10px] font-semibold tracking-widest text-gray-500 uppercase mb-1">
                  {group.label}
                </p>
                {group.intro && <p className="text-sm text-gray-400 mb-4 max-w-2xl">{group.intro}</p>}
                <div className="space-y-4">
                  {visibleSections.map((section) => (
                    <Card key={section.id} id={section.id} className="p-5 scroll-mt-6">
                      <div className="flex items-start justify-between gap-4 mb-2">
                        <div className="flex items-center gap-2.5">
                          <section.icon size={16} className="text-cyan-500 shrink-0" />
                          <h3 className="text-sm font-semibold text-gray-200">{section.title}</h3>
                          {section.audience && (
                            <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-500 border border-gray-700 rounded px-1.5 py-0.5">
                              {section.audience}
                            </span>
                          )}
                        </div>
                        {section.path && (
                          <Link
                            href={section.path}
                            className="text-xs text-cyan-500 hover:text-cyan-400 shrink-0 whitespace-nowrap"
                          >
                            Open →
                          </Link>
                        )}
                      </div>

                      <p className="text-sm text-gray-400 mb-3">{section.purpose}</p>

                      {section.actions && section.actions.length > 0 && (
                        <ul className="space-y-1.5 mb-3">
                          {section.actions.map((action, i) => (
                            <li key={i} className="flex gap-2 text-sm text-gray-300">
                              <span className="text-gray-600 shrink-0">–</span>
                              <span>{action}</span>
                            </li>
                          ))}
                        </ul>
                      )}

                      {section.note && (
                        <p className="text-xs text-amber-300/80 bg-amber-950/20 border border-amber-800/30 rounded-lg px-3 py-2">
                          {section.note}
                        </p>
                      )}
                    </Card>
                  ))}
                </div>
              </section>
            );
          })}

          {matchedIds !== null && matchedIds.size === 0 && (
            <p className="text-sm text-gray-500">No help topics match “{query}.”</p>
          )}
        </div>
      </div>
    </div>
  );
}
