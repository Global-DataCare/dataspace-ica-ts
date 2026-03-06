import type { EntityJobStatus } from './types.ts';

export type EntityAsyncJob<TRoute, TResult> = {
  thid: string;
  route: TRoute;
  status: EntityJobStatus;
  createdAt: number;
  updatedAt: number;
  result?: TResult;
  error?: string;
};

export class InMemoryEntityJobStore<TRoute, TResult> {
  private readonly jobs = new Map<string, EntityAsyncJob<TRoute, TResult>>();
  private readonly terminalTtlMs: number;

  constructor(terminalTtlSeconds = 3600) {
    this.terminalTtlMs = terminalTtlSeconds * 1000;
  }

  enqueue(thid: string, route: TRoute): EntityAsyncJob<TRoute, TResult> {
    const now = Date.now();
    const job: EntityAsyncJob<TRoute, TResult> = {
      thid,
      route,
      status: 'queued',
      createdAt: now,
      updatedAt: now,
    };
    this.jobs.set(thid, job);
    return job;
  }

  markRunning(thid: string): void {
    const job = this.jobs.get(thid);
    if (!job) return;
    job.status = 'running';
    job.updatedAt = Date.now();
  }

  markSucceeded(thid: string, result: TResult): void {
    const job = this.jobs.get(thid);
    if (!job) return;
    job.status = 'succeeded';
    job.result = result;
    job.error = undefined;
    job.updatedAt = Date.now();
  }

  markFailed(thid: string, errorMessage: string): void {
    const job = this.jobs.get(thid);
    if (!job) return;
    job.status = 'failed';
    job.error = errorMessage;
    job.updatedAt = Date.now();
  }

  get(thid: string): EntityAsyncJob<TRoute, TResult> | undefined {
    this.cleanup();
    return this.jobs.get(thid);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [thid, job] of this.jobs.entries()) {
      if (job.status === 'queued' || job.status === 'running') continue;
      if (now - job.updatedAt > this.terminalTtlMs) {
        this.jobs.delete(thid);
      }
    }
  }
}
