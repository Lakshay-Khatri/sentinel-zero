import axios from 'axios';
import type { AnalysisReport, HealthStatus } from '../types';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  // Longer than the backend's own 15 s scan timeout, so its clearer
  // "scan timed out" message reaches the user instead of a generic one.
  timeout: 25000,
});

export class ApiError extends Error {
  status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** Turn any request failure into a short, readable message. */
const toApiError = (error: unknown): ApiError => {
  if (!axios.isAxiosError(error)) {
    return new ApiError('Something went wrong while contacting the backend.');
  }
  if (error.code === 'ECONNABORTED') {
    return new ApiError('The request took too long. The target may be slow or unreachable.');
  }
  if (!error.response) {
    return new ApiError(
      `Could not reach the Sentinel Zero backend at ${API_BASE_URL}. Make sure it is running.`,
    );
  }
  const detail = (error.response.data as { detail?: unknown } | undefined)?.detail;
  // FastAPI sends a string for our own errors; anything else gets a generic message.
  const message = typeof detail === 'string' ? detail : `The backend returned an error (HTTP ${error.response.status}).`;
  return new ApiError(message, error.response.status);
};

export const healthCheck = async (): Promise<HealthStatus> => {
  const response = await api.get('/health');
  return response.data;
};

export const performScan = async (url: string): Promise<AnalysisReport> => {
  try {
    const response = await api.get('/scan', { params: { url } });
    return response.data;
  } catch (error) {
    throw toApiError(error);
  }
};
