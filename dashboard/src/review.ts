import type { Alert } from "./types";

/**
 * Where an alert sits between "the AI noticed it" and "a person signed it off".
 *
 * The distinction the whole feature rests on: an AI finding is a SUGGESTION and
 * never a resolution. Only `closed` means a human confirmed and closed it, and
 * `closed` can only come from the triage store — which the server will not
 * write without an authenticated analyst (see server/triage.js).
 */
export type ReviewKey =
  | "closed"        // a person confirmed and closed it
  | "in-review"     // a person has picked it up
  | "ai-awaiting"   // AI flagged it, nobody has looked yet
  | "untriaged";    // not flagged, not touched

export interface Review {
  key: ReviewKey;
  /** Short label for the table cell. */
  label: string;
  /** Longer, unambiguous phrasing for the drawer and tooltips. */
  detail: string;
}

export function reviewOf(alert: Alert): Review {
  const t = alert.triage;
  const flagged = alert.ai?.flagged === true;

  if (t?.status === "closed") {
    return {
      key: "closed",
      label: "human-confirmed",
      detail: `Human-confirmed and closed by ${t.updatedBy}`,
    };
  }
  if (t && t.status !== "new") {
    return {
      key: "in-review",
      label: `in review${flagged ? " · AI-flagged" : ""}`,
      detail: `Picked up by ${t.updatedBy} — ${t.status}. Not closed yet.`,
    };
  }
  if (flagged) {
    return {
      key: "ai-awaiting",
      label: "AI-flagged · awaiting review",
      detail: "Flagged by the analysis pass. No human has reviewed it yet — this is a suggestion, not a finding.",
    };
  }
  return { key: "untriaged", label: "—", detail: "Not flagged, not triaged." };
}
