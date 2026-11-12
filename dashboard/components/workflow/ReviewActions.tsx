"use client";

/**
 * The decision buttons for one resource.
 *
 * Labels come from the workflow definition, so this component never knows which
 * workflow it is serving — that is what keeps the workflows identical to
 * operate.
 */

import { Button } from "@/components/ui";
import type { WorkflowReviewAction } from "@/types/workflow";

interface Props {
  actions: WorkflowReviewAction[];
  disabled?: boolean;
  onDecide: (decision: string) => void;
}

export function ReviewActions({ actions, disabled, onDecide }: Props) {
  return (
    <div className="flex flex-wrap gap-2">
      {actions.map((action) => (
        <Button
          key={action.decision}
          variant={action.decision === "REVOKE" ? "danger" : "secondary"}
          disabled={disabled}
          title={action.description}
          onClick={() => onDecide(action.decision)}
        >
          {action.label}
        </Button>
      ))}
    </div>
  );
}
