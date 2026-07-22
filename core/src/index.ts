export { scan } from "./scan.js";
export { checkSsl } from "./ssl.js";
export { checkHeaders } from "./headers.js";

export type {
  Target,
  ScanOptions,
  ScanResult,
  HttpResult,
  RedirectHop,
  TechDetection,
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
