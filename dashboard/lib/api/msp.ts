import type { FleetOverviewResponse } from "@/types";

import { api } from "./client";

export function fetchFleetOverview() {
  return api.get<FleetOverviewResponse>("/api/v1/msp/fleet-overview", { omitTenantHeader: true });
}
