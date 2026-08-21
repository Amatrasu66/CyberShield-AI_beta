import { apiClient } from './apiClient';
import type { PortScanHistoryItem, PortScanHistoryMeta, PortScanDetail } from '../types';

export interface HistoryResponse {
  readonly scans: readonly PortScanHistoryItem[];
  readonly meta: PortScanHistoryMeta;
}

export async function fetchPortScanHistory(page = 1, limit = 20): Promise<HistoryResponse> {
  const limitClamped = Math.min(50, Math.max(1, limit));
  const pageClamped = Math.max(1, page);
  const { data, meta } = await apiClient.getWithMeta<PortScanHistoryItem[]>(
    `/scanner/ports/history?page=${pageClamped}&limit=${limitClamped}`,
  );
  const total = (meta?.total as number) ?? data.length;
  return {
    scans: data,
    meta: {
      total,
      page: (meta?.page as number) ?? pageClamped,
      limit: (meta?.limit as number) ?? limitClamped,
    },
  };
}

export async function fetchPortScanDetail(scanId: string): Promise<PortScanDetail> {
  return apiClient.get<PortScanDetail>(`/scanner/ports/history/${encodeURIComponent(scanId)}`);
}
