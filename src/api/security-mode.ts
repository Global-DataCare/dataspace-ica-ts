export type SecurityMode = 'strict' | 'compat' | 'demo';

export type IcaSecurityConfig = {
  securityMode: SecurityMode;
  jsonLegacy: boolean;
  demoAllowInsecureBearer: boolean;
  allowLegacyDidcommPlaintextMediaType: boolean;
};

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on') return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') return false;
  return fallback;
}

function parseSecurityMode(value: string | undefined): SecurityMode | undefined {
  const normalized = (value || '').trim().toLowerCase();
  if (!normalized) return undefined;
  if (normalized === 'strict' || normalized === 'compat' || normalized === 'demo') {
    return normalized;
  }
  throw new Error('Invalid SECURITY_MODE. Expected strict | compat | demo.');
}

function resolveDefaultMode(): SecurityMode {
  const legacyDemoMode = parseBooleanEnv(process.env.DEMO_MODE, false);
  return legacyDemoMode ? 'demo' : 'compat';
}

export function loadIcaSecurityConfigFromEnv(): IcaSecurityConfig {
  const securityMode = parseSecurityMode(process.env.SECURITY_MODE) || resolveDefaultMode();
  const jsonLegacyDefault = securityMode === 'strict' ? false : true;
  const jsonLegacy = parseBooleanEnv(process.env.JSON_LEGACY, jsonLegacyDefault);
  const demoAllowInsecureBearer = parseBooleanEnv(process.env.DEMO_ALLOW_INSECURE_BEARER, false);
  const allowLegacyDidcommPlaintextMediaType = parseBooleanEnv(
    process.env.ICA_ALLOW_LEGACY_DIDCOMM_PLAINTEXT_MEDIA_TYPE,
    false,
  );
  return {
    securityMode,
    jsonLegacy,
    demoAllowInsecureBearer,
    allowLegacyDidcommPlaintextMediaType,
  };
}

export function assertIcaSecurityStartupGuardrails(config: IcaSecurityConfig): void {
  const runtimeEnv = (process.env.NODE_ENV || '').trim().toLowerCase();
  if (runtimeEnv === 'production' && config.securityMode === 'demo') {
    throw new Error('SECURITY_MODE=demo is not allowed when NODE_ENV=production.');
  }
}
