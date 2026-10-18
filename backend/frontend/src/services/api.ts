import axios, { AxiosError } from 'axios';
import type { AnalysisReport, HealthStatus } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000, // 15s timeout for security scans
});

export const healthCheck = async (): Promise<HealthStatus> => {
  const response = await api.get('/health');
  return response.data;
};

export const performScan = async (url: string): Promise<AnalysisReport> => {
  try {
    const response = await api.get('/scan', {
      params: { url },
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new ApiError(error);
    }
    throw error;
  }
};

export class ApiError extends Error {
  status?: number;
  detail?: string;

  constructor(error: AxiosError) {
    const responseData = error.response?.data as any;
    super(responseData?.detail || 'An unexpected error occurred');
    this.status = error.response?.status;
    this.detail = responseData?.detail;
    this.name = 'ApiError';
  }
}
