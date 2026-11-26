import { createDnsResolver } from "@header-auditor/core";

import type { VerificationConfig } from "../config.js";
import { createDomainVerifier, type DomainVerifier } from "./domain.js";

export {
  createDomainVerifier,
  type DomainVerifier,
  evaluateTxtRecords,
  MAX_TXT_RECORDS_EXAMINED,
  VERIFICATION_RECORD_LABEL,
  VERIFICATION_VALUE_PREFIX,
  type VerificationOutcome,
  type VerificationRecord,
  verificationRecord,
  verificationRecordOrNull,
  type VerificationResult,
  VerificationUnsupportedError,
} from "./domain.js";

/** The production verifier: c-ares with the configured servers and a bounded timeout. */
export function createVerifierFromConfig(config: VerificationConfig): DomainVerifier {
  return createDomainVerifier(
    createDnsResolver({
      timeoutMs: config.dnsTimeoutMs,
      ...(config.dnsServers === undefined ? {} : { servers: config.dnsServers }),
    }),
  );
}
