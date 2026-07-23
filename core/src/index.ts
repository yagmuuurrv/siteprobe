export { scan } from "./scan.js";
export { checkSsl } from "./ssl.js";
export { checkHeaders } from "./headers.js";
export { detectTech } from "./tech.js";
export { SIGNATURES } from "./signatures.js";

export type {
  Target,
  ScanOptions,
  ScanResult,
  HttpResult,
  RedirectHop,
  CveMatch,
} from "./types.js";
export type {
  SslResult,
  SslCertInfo,
  SslFlags,
  CheckSslOptions,
} from "./ssl.js";
export type {
  HeadersResult,
  HeaderFinding,
  Severity,
  ResponseHeaders,
} from "./headers.js";
export type { TechResult, Confidence } from "./tech.js";
export type { Signature, SignatureMatch } from "./signatures.js";
