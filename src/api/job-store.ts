import type { VerificationJob, VerifyRouteContext } from './types.ts';

export class InMemoryVerificationJobStore {
  private readonly jobs = new Map<string, VerificationJob>();
  private readonly terminalTtlMs: number;

  constructor(terminalTtlSeconds = 3600) {
    this.terminalTtlMs = terminalTtlSeconds * 1000;
  }

  enqueue(thid: string, route: VerifyRouteContext): VerificationJob {
    const now = Date.now();
    const job: VerificationJob = {
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

  markSucceeded(thid: string, result: VerificationJob['result']): void {
    const job = this.jobs.get(thid);
    if (!job) return;
    job.status = 'succeeded';
    job.result = result;
    job.error = undefined;
    job.errorDetails = undefined;
    job.updatedAt = Date.now();
  }

  markFailed(
    thid: string,
    errorMessage: string,
    errorDetails?: VerificationJob['errorDetails'],
  ): void {
    const job = this.jobs.get(thid);
    if (!job) return;
    job.status = 'failed';
    job.error = errorMessage;
    job.errorDetails = errorDetails;
    job.updatedAt = Date.now();
  }

  get(thid: string): VerificationJob | undefined {
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
