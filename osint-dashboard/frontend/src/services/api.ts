import type { ModuleResult, ReportPayload } from '../types/osint';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

export type ScanStreamHandlers = {
  onModuleStarted: (module: string) => void;
  onModuleFinished: (result: ModuleResult) => void;
  onReport: (payload: ReportPayload) => void;
  onError: (detail: string) => void;
};

export function openScanStream(target: string, handlers: ScanStreamHandlers): EventSource {
  const url = `${API_BASE_URL}/scan?target=${encodeURIComponent(target)}`;
  const es = new EventSource(url);
  let settled = false;
  const finish = () => {
    settled = true;
    es.close();
  };

  es.addEventListener('module_started', (e) => {
    handlers.onModuleStarted(JSON.parse((e as MessageEvent).data).module);
  });
  es.addEventListener('module_finished', (e) => {
    handlers.onModuleFinished(JSON.parse((e as MessageEvent).data) as ModuleResult);
  });
  es.addEventListener('report', (e) => {
    handlers.onReport(JSON.parse((e as MessageEvent).data) as ReportPayload);
    finish();
  });
  es.addEventListener('error', (e) => {
    if (settled) return;
    const raw = (e as MessageEvent).data;
    if (raw) {
      handlers.onError(JSON.parse(raw).detail ?? 'Scan error.');
    } else {
      handlers.onError('Connection lost.');
    }
    finish();
  });

  return es;
}
