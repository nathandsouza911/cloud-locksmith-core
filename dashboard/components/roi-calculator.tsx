"use client";

import Link from "next/link";
import { useState, useEffect, useRef } from "react";

function useAnimatedNumber(target: number, duration = 500) {
  const [current, setCurrent] = useState(target);
  const rafRef = useRef<number | null>(null);
  const startRef = useRef<number | null>(null);
  const fromRef = useRef(target);

  useEffect(() => {
    const from = fromRef.current;
    const to = target;
    if (from === to) return;

    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    startRef.current = null;

    const animate = (timestamp: number) => {
      if (!startRef.current) startRef.current = timestamp;
      const elapsed = timestamp - startRef.current;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const value = Math.round(from + (to - from) * eased);
      setCurrent(value);
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate);
      } else {
        fromRef.current = to;
      }
    };
    rafRef.current = requestAnimationFrame(animate);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [target, duration]);

  return current;
}

const ArrowRight = () => (
  <svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ width: 15, height: 15 }}>
    <path
      d="M3 8h10M9 4l4 4-4 4"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

export function ROICalculator() {
  const [hourlyRate, setHourlyRate] = useState(100);
  const [incidents, setIncidents] = useState(4);
  const [fixHours, setFixHours] = useState(5);

  const annualLaborCost = incidents * fixHours * hourlyRate;
  const animatedCost = useAnimatedNumber(annualLaborCost);
  const speedMultiple = fixHours * 60;

  return (
    <section id="roi-calculator" className="roi-section">
      <div className="container">
        <p className="section-label" style={{ textAlign: "center" }}>
          What&apos;s Your Exposure?
        </p>
        <h2 className="section-title" style={{ textAlign: "center", maxWidth: 680, margin: "0 auto 16px" }}>
          What Are Your Identity Risks Costing You?
        </h2>
        <p className="section-body" style={{ textAlign: "center", margin: "0 auto 52px", maxWidth: 540 }}>
          Enter your numbers to see the real cost of manual incident recovery — before the next mistake
          happens.
        </p>

        <div className="roi-grid">
          {/* ── LEFT: Inputs ── */}
          <div className="roi-inputs">
            <div className="roi-input-group">
              <div className="roi-input-header">
                <label>Admin Hourly Rate</label>
                <span className="roi-input-value">${hourlyRate}/hr</span>
              </div>
              <div className="roi-number-input">
                <span>$</span>
                <input
                  type="number"
                  min={20}
                  max={500}
                  value={hourlyRate}
                  onChange={(e) => setHourlyRate(Math.max(0, Number(e.target.value)))}
                />
                <span>/hr</span>
              </div>
            </div>

            <div className="roi-input-group">
              <div className="roi-input-header">
                <label>Incidents / Misconfigs per Year</label>
                <span className="roi-input-value">{incidents}</span>
              </div>
              <input
                type="range"
                min={0}
                max={20}
                step={1}
                value={incidents}
                onChange={(e) => setIncidents(Number(e.target.value))}
                className="roi-slider"
                style={{ "--roi-pct": `${(incidents / 20) * 100}%` } as React.CSSProperties}
              />
              <div className="roi-slider-range">
                <span>0</span>
                <span>20</span>
              </div>
            </div>

            <div className="roi-input-group">
              <div className="roi-input-header">
                <label>Avg. time to manually fix one incident (hours)</label>
                <span className="roi-input-value">
                  {fixHours} hr{fixHours !== 1 ? "s" : ""}
                </span>
              </div>
              <input
                type="range"
                min={1}
                max={8}
                step={1}
                value={fixHours}
                onChange={(e) => setFixHours(Number(e.target.value))}
                className="roi-slider"
                style={{ "--roi-pct": `${((fixHours - 1) / 7) * 100}%` } as React.CSSProperties}
              />
              <div className="roi-slider-range">
                <span>1 hr</span>
                <span>8 hrs</span>
              </div>
            </div>

            <div className="roi-tooltip-box">
              <span className="roi-tooltip-icon">ℹ</span>
              <div>
                <strong>How this is calculated</strong>
                <p>
                  Each misconfiguration — a wrong permission, a missed offboarding, an accidental policy
                  change — takes your admin hours to diagnose and manually reverse. Multiply that across a
                  year and the cost adds up fast.
                </p>
              </div>
            </div>
          </div>

          {/* ── RIGHT: Results ── */}
          <div className="roi-results">
            <div className="roi-total-card">
              <p className="roi-total-label">Annual admin cost of identity incidents</p>
              <div className="roi-total-amount">${animatedCost.toLocaleString()}</div>
              <p className="roi-total-disclaimer">Does not include downtime, breaches, or audit failures.</p>
            </div>

            <div className="roi-breakdown">
              <div className="roi-metric-card roi-speed-card">
                <div className="roi-metric-label" style={{ marginBottom: 14 }}>
                  Recovery Time: Manual vs. Cloud Locksmith
                </div>
                <div className="roi-speed-compare">
                  <div className="roi-speed-item roi-speed-slow">
                    <div className="roi-speed-value">
                      {fixHours} hr{fixHours !== 1 ? "s" : ""}
                    </div>
                    <div className="roi-speed-desc">
                      Manual
                      <br />
                      remediation
                    </div>
                  </div>
                  <div className="roi-speed-arrow">→</div>
                  <div className="roi-speed-item roi-speed-fast">
                    <div className="roi-speed-value">&lt;60s</div>
                    <div className="roi-speed-desc">
                      Cloud Locksmith
                      <br />
                      with rollback
                    </div>
                  </div>
                </div>
                <div className="roi-speed-badge">
                  {speedMultiple}× faster than manual remediation ({fixHours} hr{fixHours !== 1 ? "s" : ""} vs
                  60 sec)
                </div>
              </div>
            </div>

            <div className="roi-cta">
              <Link
                href="/preview-login"
                className="btn-primary"
                style={{ display: "flex", justifyContent: "center", width: "100%" }}
              >
                Run Free Security Scan <ArrowRight />
              </Link>
              <p className="roi-cta-sub">See your real Microsoft 365 security gaps in 60 seconds</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
