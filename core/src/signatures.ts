/**
 * Technology fingerprints — DATA ONLY, no logic. `tech.ts` interprets these.
 *
 * Each signature says how to recognise a product (which header / cookie / HTML
 * marker) and how to pull a version out of the response. Confidence is NOT
 * stored here: it is derived from WHICH match fired (see `tech.ts`).
 *
 * v1 keeps the list small (~25). Passive markers only.
 *
 * Filename convention: a pattern that matches an asset filename must tolerate a
 * version sitting between the product name and the extension
 * (`bootstrap-5.3.3.min.js`) and must cover all three separators CDNs use:
 * `-` (bootstrap-5.3.3), `@` (unpkg: bootstrap@5.3.3) and `/` (cdnjs:
 * /libs/bootstrap/5.3.3/). The same applies to `versionPatterns`.
 */

/** Where a signature can look. All fields optional; any match counts. */
export interface SignatureMatch {
  /** A response header, optionally constrained by a pattern on its value. */
  header?: { name: string; pattern?: RegExp };
  /** A cookie name/value pattern (tested against each cookie string). */
  cookie?: RegExp;
  /** A pattern tested against the whole HTML body. */
  html?: RegExp;
  /** A pattern tested against `<meta name="generator">` content. */
  metaGenerator?: RegExp;
  /** A pattern tested against each `<script src>` URL. */
  scriptSrc?: RegExp;
}

export interface Signature {
  name: string;
  category: string;
  /** CPE vendor, or null when unknown. */
  vendor: string | null;
  /** CPE product, or null when unknown. */
  product: string | null;
  match: SignatureMatch;
  /** Version capture patterns (group 1 = version); tried in order. */
  versionPatterns: RegExp[];
}

export const SIGNATURES: Signature[] = [
  // --- Web servers ---
  {
    name: "nginx",
    category: "web-server",
    vendor: "nginx",
    product: "nginx",
    match: { header: { name: "Server", pattern: /nginx/i } },
    versionPatterns: [/nginx\/(\d+(?:\.\d+)+)/i],
  },
  {
    name: "Apache",
    category: "web-server",
    vendor: "apache",
    product: "http_server",
    match: { header: { name: "Server", pattern: /apache/i } },
    versionPatterns: [/apache\/(\d+(?:\.\d+)+)/i],
  },
  {
    name: "IIS",
    category: "web-server",
    vendor: "microsoft",
    product: "internet_information_services",
    match: { header: { name: "Server", pattern: /microsoft-iis/i } },
    versionPatterns: [/microsoft-iis\/(\d+(?:\.\d+)+)/i],
  },
  {
    name: "LiteSpeed",
    category: "web-server",
    vendor: "litespeedtech",
    product: "litespeed_web_server",
    match: { header: { name: "Server", pattern: /litespeed/i } },
    versionPatterns: [/litespeed\/(\d+(?:\.\d+)+)/i],
  },

  // --- CDN ---
  {
    name: "Cloudflare",
    category: "cdn",
    vendor: "cloudflare",
    product: "cloudflare",
    match: { header: { name: "Server", pattern: /cloudflare/i } },
    versionPatterns: [],
  },

  // --- Programming language ---
  {
    name: "PHP",
    category: "programming-language",
    vendor: "php",
    product: "php",
    match: {
      header: { name: "X-Powered-By", pattern: /php/i },
      cookie: /PHPSESSID/i,
    },
    versionPatterns: [/php\/(\d+(?:\.\d+)+)/i],
  },

  // --- Web frameworks ---
  {
    name: "ASP.NET",
    category: "web-framework",
    vendor: "microsoft",
    product: "asp.net",
    match: { header: { name: "X-Powered-By", pattern: /asp\.net/i } },
    versionPatterns: [],
  },
  {
    name: "Next.js",
    category: "web-framework",
    vendor: "vercel",
    product: "next.js",
    match: {
      header: { name: "X-Powered-By", pattern: /next\.js/i },
      html: /\/_next\/static\//i,
    },
    versionPatterns: [],
  },
  {
    name: "Laravel",
    category: "web-framework",
    vendor: "laravel",
    product: "laravel",
    match: { cookie: /laravel_session|XSRF-TOKEN/i },
    versionPatterns: [],
  },
  {
    name: "Angular",
    category: "web-framework",
    vendor: "angular",
    product: "angular",
    match: { html: /ng-version=["'][\d.]+["']/i },
    versionPatterns: [/ng-version=["'](\d+(?:\.\d+)*)["']/i],
  },

  // --- CMS ---
  {
    name: "WordPress",
    category: "cms",
    vendor: "wordpress",
    product: "wordpress",
    match: {
      metaGenerator: /WordPress/i,
      html: /\/wp-content\//i,
      cookie: /wordpress_|wp-settings-/i,
    },
    versionPatterns: [/WordPress\s+(\d+(?:\.\d+)+)/i],
  },
  {
    name: "Joomla",
    category: "cms",
    vendor: "joomla",
    product: "joomla",
    match: {
      metaGenerator: /Joomla/i,
      html: /\/media\/(?:jui|system)\//i,
    },
    versionPatterns: [/Joomla!?\s*(\d+(?:\.\d+)+)/i],
  },
  {
    name: "Drupal",
    category: "cms",
    vendor: "drupal",
    product: "drupal",
    match: {
      header: { name: "X-Generator", pattern: /drupal/i },
      html: /\/sites\/(?:all|default)\/|drupal\.js/i,
    },
    versionPatterns: [/Drupal\s+(\d+(?:\.\d+)*)/i],
  },

  // --- JavaScript libraries ---
  {
    name: "jQuery",
    category: "javascript-library",
    vendor: "jquery",
    product: "jquery",
    match: { scriptSrc: /jquery/i },
    versionPatterns: [/jquery[-@/](\d+(?:\.\d+)+)/i],
  },
  {
    name: "React",
    category: "javascript-library",
    vendor: "facebook",
    product: "react",
    match: {
      scriptSrc:
        /react(?:-dom)?(?:[-@/.]\d[\d.]*)?(?:\.production|\.development)?(?:\.min)?\.js/i,
      html: /data-reactroot|__REACT_DEVTOOLS/i,
    },
    versionPatterns: [/react(?:-dom)?[-@/](\d+(?:\.\d+)+)/i],
  },
  {
    name: "Vue",
    category: "javascript-library",
    vendor: "vuejs",
    product: "vue",
    match: {
      scriptSrc: /vue[-@/.]/i,
      html: /data-v-[0-9a-f]{6,8}=|__vue__/i,
    },
    versionPatterns: [/vue[-@/](\d+(?:\.\d+)+)/i],
  },

  // --- UI framework ---
  {
    name: "Bootstrap",
    category: "ui-framework",
    vendor: "getbootstrap",
    product: "bootstrap",
    match: {
      scriptSrc: /bootstrap(?:[-@/.]\d[\d.]*)?(?:\.bundle)?(?:\.min)?\.js/i,
      html: /bootstrap(?:[-@/.]\d[\d.]*)?(?:\.min)?\.css/i,
    },
    versionPatterns: [
      /Bootstrap\s+v(\d+(?:\.\d+)+)/i,
      /bootstrap[-@/](\d+(?:\.\d+)+)/i,
    ],
  },

  // --- Analytics ---
  {
    name: "Google Analytics",
    category: "analytics",
    vendor: "google",
    product: "analytics",
    match: {
      html: /googletagmanager\.com\/gtag\/js|google-analytics\.com\/(?:analytics|ga)\.js|gtag\(\s*['"]config['"]/i,
    },
    versionPatterns: [],
  },

  // --- Fonts ---
  {
    name: "Font Awesome",
    category: "font",
    vendor: "fonticons",
    product: "font_awesome",
    match: { html: /font-?awesome/i },
    versionPatterns: [
      /font-?awesome[^"'()]*?(\d+(?:\.\d+)+)/i,
      /fontawesome[-@/](\d+(?:\.\d+)+)/i,
    ],
  },
  {
    name: "Google Fonts",
    category: "font",
    vendor: "google",
    product: "fonts",
    match: { html: /fonts\.googleapis\.com|fonts\.gstatic\.com/i },
    versionPatterns: [],
  },

  // --- Hosting panels ---
  {
    name: "cPanel",
    category: "hosting-panel",
    vendor: "cpanel",
    product: "cpanel",
    match: { header: { name: "Server", pattern: /cpsrvd|cpanel/i } },
    versionPatterns: [/cpsrvd\/(\d+(?:\.\d+)+)/i],
  },
  {
    name: "Plesk",
    category: "hosting-panel",
    vendor: "plesk",
    product: "obsidian",
    match: {
      header: { name: "X-Powered-By", pattern: /plesk/i },
      cookie: /PLESKSESSID/i,
    },
    versionPatterns: [],
  },
];
