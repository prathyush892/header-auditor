/**
 * What fetching one well-known file produced. Shared by the security.txt and
 * robots.txt checks so they grade plain data and never touch the network.
 */
import type { ScanErrorCode } from "../scan/errors.js";
import type { RedirectHop } from "../scan/scan-url.js";

export type WellKnownObservation =
  | {
      readonly kind: "found";
      /** The URL requested. */
      readonly url: string;
      /** The path requested (e.g. `/robots.txt`). */
      readonly path: string;
      /** Where the redirect chain ended. */
      readonly finalUrl: string;
      readonly statusCode: number;
      /** Lower-cased media type of the response, "" when absent. */
      readonly mediaType: string;
      readonly text: string;
      /** True when the body was larger than the read limit. */
      readonly truncated: boolean;
      readonly redirects: readonly RedirectHop[];
    }
  | {
      readonly kind: "missing";
      readonly url: string;
      readonly path: string;
      /** Final status, when there was a response. */
      readonly statusCode: number;
      /** Why it counts as missing ("HTTP 404", "served as HTML"...). */
      readonly reason: string;
    }
  | {
      readonly kind: "error";
      readonly url: string;
      readonly path: string;
      /** Why the request failed (timeout, network...). */
      readonly code: ScanErrorCode;
    };
