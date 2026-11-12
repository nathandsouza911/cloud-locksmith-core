import type {
  NormalizedTimelinePoint,
  PostureTimelinePoint,
  PostureTrendPoint,
  ScoreBand,
  TimelineTrendSummary,
} from "@/types";

type TimelineSource = PostureTimelinePoint | PostureTrendPoint | Record<string, unknown>;

export function scoreBandLabel(scoreBand?: ScoreBand | null): string {
  switch (scoreBand) {
    case "GOOD":
      return "Good";
    case "MODERATE":
      return "Moderate";
    case "HIGH":
      return "High";
    case "CRITICAL":
      return "Critical";
    default:
      return "Awaiting scan";
  }
}

export function scoreBandAccent(scoreBand?: ScoreBand | null): string {
  switch (scoreBand) {
    case "GOOD":
      return "text-cyan-400";
    case "MODERATE":
      return "text-yellow-400";
    case "HIGH":
      return "text-orange-400";
    case "CRITICAL":
      return "text-red-400";
    default:
      return "text-gray-400";
  }
}

function toIsoDate(value: string): string | null {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().slice(0, 10);
}

function scoreFromValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function dayOffset(base: Date, offset: number): Date {
  const copy = new Date(base);
  copy.setUTCDate(copy.getUTCDate() + offset);
  return copy;
}

export function normalizeTimeline(data: TimelineSource[] | null | undefined): NormalizedTimelinePoint[] {
  if (!Array.isArray(data) || data.length === 0) return [];

  const byDate = new Map<string, number | null>();

  for (const item of data) {
    if (!item || typeof item !== "object") continue;
    const record = item as Record<string, unknown>;
    const rawDate =
      typeof record.date === "string"
        ? record.date
        : typeof record.timestamp === "string"
          ? record.timestamp
          : null;
    const date = rawDate ? toIsoDate(rawDate) : null;
    if (!date) continue;
    byDate.set(date, scoreFromValue(record.score));
  }

  return Array.from(byDate.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([date, score]) => ({ date, score }));
}

export function getLast14Days(
  data: TimelineSource[] | NormalizedTimelinePoint[] | null | undefined,
): NormalizedTimelinePoint[] {
  const normalized = normalizeTimeline(data as TimelineSource[]);
  const today = new Date();
  const end = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
  const start = dayOffset(end, -13);
  const values = new Map(normalized.map((point) => [point.date, point.score]));

  let lastKnownScore: number | null = null;
  for (const point of normalized) {
    if (point.date <= start.toISOString().slice(0, 10) && point.score !== null) {
      lastKnownScore = point.score;
    }
  }

  const result: NormalizedTimelinePoint[] = [];
  for (let offset = 0; offset < 14; offset += 1) {
    const currentDate = dayOffset(start, offset).toISOString().slice(0, 10);
    const currentScore = values.has(currentDate) ? (values.get(currentDate) ?? null) : lastKnownScore;
    if (currentScore !== null) {
      lastKnownScore = currentScore;
    }
    result.push({ date: currentDate, score: currentScore });
  }

  return result;
}

export function calculateTrend(
  data: TimelineSource[] | NormalizedTimelinePoint[] | null | undefined,
): TimelineTrendSummary {
  const points = getLast14Days(data);
  const scoredPoints = points.filter(
    (point): point is { date: string; score: number } => point.score !== null,
  );

  if (scoredPoints.length < 2) {
    return {
      label: "Stable",
      delta: 0,
      direction: "flat",
      summary: "Not enough data yet to calculate a posture trend.",
    };
  }

  const latest = scoredPoints[scoredPoints.length - 1];
  const previous = scoredPoints[0];
  const delta = latest.score - previous.score;
  const label = delta > 1 ? "Improving" : delta < -1 ? "Declining" : "Stable";
  const direction = delta > 1 ? "up" : delta < -1 ? "down" : "flat";
  const signedDelta = delta > 0 ? `+${delta}` : `${delta}`;

  return {
    label,
    delta,
    direction,
    summary:
      label === "Stable"
        ? "Your identity posture has remained stable over the last 14 days."
        : `Your identity posture ${label === "Improving" ? "improved" : "declined"} by ${signedDelta} points over the last 14 days.`,
  };
}
