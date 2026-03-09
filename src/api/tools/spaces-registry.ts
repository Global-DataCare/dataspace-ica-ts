import type { DataspaceScope, DataspaceSyncTarget } from './dataspace-sync.ts';
import { dedupeTargets, loadDataspaceSyncTargetsFromEnv } from './dataspace-sync.ts';

export type SpacesPublicTarget = {
  resourceType: 'RuntimePlatform';
  name?: string;
  identifier: string;
  url?: string;
};

function scopeKey(scope: DataspaceScope): string {
  return `${scope.tenantId.toLowerCase()}|${scope.jurisdiction.toUpperCase()}|${scope.sector.toLowerCase()}`;
}

function cloneTarget(target: DataspaceSyncTarget): DataspaceSyncTarget {
  return {
    ...(target.name ? { name: target.name } : {}),
    did: target.did,
    ...(target.endpointUrl ? { endpointUrl: target.endpointUrl } : {}),
    ...(target.apiKey ? { apiKey: target.apiKey } : {}),
  };
}

function toPublicTarget(target: DataspaceSyncTarget): SpacesPublicTarget {
  return {
    resourceType: 'RuntimePlatform',
    ...(target.name ? { name: target.name } : {}),
    identifier: target.did,
    ...(target.endpointUrl ? { url: target.endpointUrl } : {}),
  };
}

export class SpacesRegistry {
  private readonly byScope = new Map<string, DataspaceSyncTarget[]>();
  private readonly defaultTargets: DataspaceSyncTarget[];
  private readonly rootCaDid: string;

  constructor(defaultTargets: DataspaceSyncTarget[] = loadDataspaceSyncTargetsFromEnv()) {
    this.defaultTargets = dedupeTargets(defaultTargets);
    this.rootCaDid = String(process.env.ICA_ROOT_CA_DID || '').trim();
  }

  getRootCaDid(): string {
    return this.rootCaDid;
  }

  private resolveSource(scope: DataspaceScope): DataspaceSyncTarget[] {
    const key = scopeKey(scope);
    const scoped = this.byScope.get(key);
    return scoped && scoped.length ? scoped : this.defaultTargets;
  }

  list(scope: DataspaceScope): SpacesPublicTarget[] {
    return this.resolveSource(scope).map((target) => toPublicTarget(cloneTarget(target)));
  }

  resolveForSync(scope: DataspaceScope): DataspaceSyncTarget[] {
    return this.resolveSource(scope).map((target) => cloneTarget(target));
  }

  replace(scope: DataspaceScope, targets: DataspaceSyncTarget[]): SpacesPublicTarget[] {
    const key = scopeKey(scope);
    const normalized = dedupeTargets(targets);
    this.byScope.set(key, normalized);
    return this.list(scope);
  }
}
