import { api } from "./client";
import type {
  Campaign,
  CampaignPreviewResponse,
  CreateCampaignPayload,
  ApproveCampaignPayload,
} from "@/types/campaign";

const BASE = "/api/v1/fleet/campaigns";

export const listCampaigns = () => api.get<Campaign[]>(BASE);

export const getCampaign = (id: string) => api.get<Campaign>(`${BASE}/${id}`);

export const createCampaign = (payload: CreateCampaignPayload) => api.post<Campaign>(BASE, payload);

export const approveCampaign = (id: string, payload: ApproveCampaignPayload) =>
  api.post<Campaign>(`${BASE}/${id}/approve`, payload);

export const executeCampaign = (id: string) => api.post<Campaign>(`${BASE}/${id}/execute`);

export const rollbackCampaign = (id: string) => api.post<Campaign>(`${BASE}/${id}/rollback`);

export const cancelCampaign = (id: string) => api.post<Campaign>(`${BASE}/${id}/cancel`);

export const getCampaignPreview = (
  controlIds: string[],
  tenantIds: string[],
): Promise<CampaignPreviewResponse> => {
  const params = new URLSearchParams();
  controlIds.forEach((id) => params.append("control_ids", id));
  tenantIds.forEach((id) => params.append("target_tenant_ids", id));
  return api.get<CampaignPreviewResponse>(`${BASE}/preview?${params.toString()}`);
};
