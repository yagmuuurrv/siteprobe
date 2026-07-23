import { describe, expect, it } from "vitest";

import type { ResponseHeaders } from "../src/headers.js";
import { detectTech, type TechResult } from "../src/tech.js";

/** Run detection and return the result for one product, or undefined. */
function detect(
  name: string,
  headers: ResponseHeaders = {},
  html = "",
  cookies: string[] = [],
): TechResult | undefined {
  return detectTech(headers, html, cookies).find((t) => t.name === name);
}

/** Same, but fails loudly when the product was not detected. */
function detected(
  name: string,
  headers: ResponseHeaders = {},
  html = "",
  cookies: string[] = [],
): TechResult {
  const hit = detect(name, headers, html, cookies);
  if (hit === undefined) throw new Error(`${name} was not detected`);
  return hit;
}

describe("detectTech", () => {
  it("detects nothing in an empty response", () => {
    expect(detectTech({}, "", [])).toEqual([]);
  });

  it("detects nothing in a plain HTML page with no markers", () => {
    const html = "<html><head><title>Hello</title></head><body>hi</body></html>";
    expect(detectTech({ "content-type": "text/html" }, html, [])).toEqual([]);
  });

  describe("header matches", () => {
    it("detects nginx with its version and full evidence", () => {
      const tech = detected("nginx", { server: "nginx/1.24.0" });

      expect(tech.version).toBe("1.24.0");
      expect(tech.confidence).toBe("high");
      expect(tech.evidence).toBe("Server: nginx/1.24.0");
      expect(tech.vendor).toBe("nginx");
      expect(tech.product).toBe("nginx");
    });

    it("matches the header name case-insensitively", () => {
      expect(detect("nginx", { SERVER: "nginx/1.24.0" })).toBeDefined();
      expect(detect("nginx", { Server: "nginx" })).toBeDefined();
    });

    it("leaves the version null when the banner carries none", () => {
      const tech = detected("nginx", { server: "nginx" });

      expect(tech.version).toBeNull();
      expect(tech.confidence).toBe("high");
    });

    it("leaves the version null for a signature with no version patterns", () => {
      const tech = detected("Cloudflare", { server: "cloudflare" });

      expect(tech.version).toBeNull();
    });

    it("folds a repeated header into one comma-joined value", () => {
      const tech = detected("nginx", { server: ["nginx/1.24.0", "extra"] });

      expect(tech.evidence).toBe("Server: nginx/1.24.0, extra");
      expect(tech.version).toBe("1.24.0");
    });

    it("ignores a header whose value does not match the pattern", () => {
      expect(detect("nginx", { server: "Apache/2.4.58" })).toBeUndefined();
      expect(detect("Apache", { server: "Apache/2.4.58" })).toBeDefined();
    });

    it("detects Drupal from X-Generator", () => {
      const tech = detected("Drupal", { "x-generator": "Drupal 10 (https://www.drupal.org)" });

      expect(tech.version).toBe("10");
      expect(tech.confidence).toBe("high");
    });
  });

  describe("meta generator matches", () => {
    it("detects WordPress and its version", () => {
      const html = '<meta name="generator" content="WordPress 6.5.2" />';
      const tech = detected("WordPress", {}, html);

      expect(tech.version).toBe("6.5.2");
      expect(tech.confidence).toBe("high");
      expect(tech.evidence).toBe("meta generator: WordPress 6.5.2");
    });

    it("reads the tag with content before name", () => {
      const html = '<meta content="Joomla! 4.4.3" name="generator">';
      const tech = detected("Joomla", {}, html);

      expect(tech.version).toBe("4.4.3");
      expect(tech.confidence).toBe("high");
    });

    it("accepts single-quoted attributes", () => {
      expect(detect("WordPress", {}, "<meta name='generator' content='WordPress 6.5'>")).toBeDefined();
    });
  });

  describe("cookie matches", () => {
    it("detects PHP from PHPSESSID at medium confidence", () => {
      const tech = detected("PHP", {}, "", ["PHPSESSID=abc123; path=/"]);

      expect(tech.confidence).toBe("medium");
      expect(tech.evidence).toContain("PHPSESSID");
      // The cookie name carries no version.
      expect(tech.version).toBeNull();
    });

    it("detects Laravel from its session cookie", () => {
      expect(detect("Laravel", {}, "", ["laravel_session=xyz"])).toBeDefined();
    });

    it("scans every cookie, not just the first", () => {
      expect(
        detect("Plesk", {}, "", ["foo=1", "bar=2", "PLESKSESSID=deadbeef"]),
      ).toBeDefined();
    });
  });

  describe("script src matches", () => {
    it("detects jQuery with its version at low confidence", () => {
      const html = '<script src="/assets/jquery-3.7.1.min.js"></script>';
      const tech = detected("jQuery", {}, html);

      expect(tech.version).toBe("3.7.1");
      expect(tech.confidence).toBe("low");
      expect(tech.evidence).toBe("script src: /assets/jquery-3.7.1.min.js");
    });

    it("reads the version from an @-pinned CDN URL", () => {
      const html = '<script src="https://cdn.jsdelivr.net/npm/vue@3.4.21/dist/vue.js"></script>';

      expect(detected("Vue", {}, html).version).toBe("3.4.21");
    });
  });

  /**
   * A CDN can put the version between the product name and the extension, with
   * any of three separators: `-` (bootstrap-5.3.3.min.js), `@` (unpkg) and `/`
   * (cdnjs). Every filename pattern must survive all three.
   */
  describe("versioned asset filenames", () => {
    /** `<script src>` markup for a single URL. */
    const script = (src: string): string => `<script src="${src}"></script>`;

    describe("Bootstrap", () => {
      it("detects a hyphen-versioned script filename", () => {
        const tech = detected("Bootstrap", {}, script("/js/bootstrap-5.3.3.min.js"));

        expect(tech.version).toBe("5.3.3");
        expect(tech.confidence).toBe("low");
        expect(tech.evidence).toBe("script src: /js/bootstrap-5.3.3.min.js");
      });

      it("detects a hyphen-versioned stylesheet", () => {
        const tech = detected(
          "Bootstrap",
          {},
          '<link href="/css/bootstrap-5.3.3.min.css" rel="stylesheet">',
        );

        expect(tech.version).toBe("5.3.3");
        expect(tech.confidence).toBe("medium");
      });

      it("detects an @-pinned unpkg URL", () => {
        const html = script("https://unpkg.com/bootstrap@5.3.3/dist/js/bootstrap.min.js");

        expect(detected("Bootstrap", {}, html).version).toBe("5.3.3");
      });

      it("detects a /-versioned cdnjs URL", () => {
        const html = script(
          "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.3/js/bootstrap.min.js",
        );

        expect(detected("Bootstrap", {}, html).version).toBe("5.3.3");
      });

      it("still detects the unversioned filenames", () => {
        expect(detect("Bootstrap", {}, script("/js/bootstrap.js"))).toBeDefined();
        expect(detect("Bootstrap", {}, script("/js/bootstrap.min.js"))).toBeDefined();
        expect(
          detect("Bootstrap", {}, script("/js/bootstrap.bundle.min.js")),
        ).toBeDefined();
        expect(detected("Bootstrap", {}, script("/js/bootstrap.min.js")).version).toBeNull();
      });
    });

    describe("React", () => {
      it("detects a hyphen-versioned script filename", () => {
        const tech = detected("React", {}, script("/js/react-18.2.0.min.js"));

        expect(tech.version).toBe("18.2.0");
      });

      it("detects a hyphen-versioned react-dom filename", () => {
        const tech = detected("React", {}, script("/js/react-dom-18.2.0.min.js"));

        expect(tech.version).toBe("18.2.0");
      });

      it("detects an @-pinned unpkg URL", () => {
        const html = script("https://unpkg.com/react@18.2.0/umd/react.production.min.js");

        expect(detected("React", {}, html).version).toBe("18.2.0");
      });

      it("detects a /-versioned cdnjs URL", () => {
        const html = script(
          "https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js",
        );

        expect(detected("React", {}, html).version).toBe("18.2.0");
      });

      it("still detects the unversioned CDN filenames", () => {
        expect(
          detect("React", {}, script("/js/react.production.min.js")),
        ).toBeDefined();
        expect(
          detect("React", {}, script("/js/react-dom.development.js")),
        ).toBeDefined();
      });
    });

    describe("Vue", () => {
      it("detects a /-versioned cdnjs URL", () => {
        // The `/` separator was previously missing from the Vue script pattern.
        const html = script(
          "https://cdnjs.cloudflare.com/ajax/libs/vue/3.4.21/runtime.global.min.js",
        );
        const tech = detected("Vue", {}, html);

        expect(tech.version).toBe("3.4.21");
        expect(tech.confidence).toBe("low");
      });

      it("detects a hyphen-versioned script filename", () => {
        expect(detected("Vue", {}, script("/js/vue-3.4.21.min.js")).version).toBe(
          "3.4.21",
        );
      });

      it("still detects the unversioned filename", () => {
        expect(detect("Vue", {}, script("/js/vue.global.prod.js"))).toBeDefined();
      });
    });

    describe("jQuery", () => {
      it("covers all three separators", () => {
        expect(detected("jQuery", {}, script("/js/jquery-3.7.1.min.js")).version).toBe(
          "3.7.1",
        );
        expect(
          detected("jQuery", {}, script("https://unpkg.com/jquery@3.7.1/dist/jquery.min.js"))
            .version,
        ).toBe("3.7.1");
        expect(
          detected(
            "jQuery",
            {},
            script("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"),
          ).version,
        ).toBe("3.7.1");
      });
    });

    describe("Font Awesome", () => {
      it("covers all three separators", () => {
        expect(
          detected("Font Awesome", {}, '<link href="/css/font-awesome-4.7.0.min.css">')
            .version,
        ).toBe("4.7.0");
        expect(
          detected(
            "Font Awesome",
            {},
            '<link href="https://unpkg.com/@fortawesome/fontawesome-free@6.5.2/css/all.min.css">',
          ).version,
        ).toBe("6.5.2");
        expect(
          detected(
            "Font Awesome",
            {},
            '<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">',
          ).version,
        ).toBe("6.5.2");
      });
    });
  });

  describe("html body matches", () => {
    it("detects WordPress from a /wp-content/ path at medium confidence", () => {
      const html = '<link href="/wp-content/themes/x/style.css" rel="stylesheet">';
      const tech = detected("WordPress", {}, html);

      expect(tech.confidence).toBe("medium");
      expect(tech.evidence).toContain("/wp-content/");
      expect(tech.version).toBeNull();
    });

    it("detects Angular and reads ng-version", () => {
      const tech = detected("Angular", {}, '<app-root ng-version="17.3.0"></app-root>');

      expect(tech.version).toBe("17.3.0");
      expect(tech.confidence).toBe("medium");
    });

    it("detects Next.js from a /_next/static/ asset path", () => {
      expect(detect("Next.js", {}, '<script src="/_next/static/chunks/main.js">')).toBeDefined();
    });
  });

  describe("confidence resolution", () => {
    it("keeps the highest-confidence hit when several fields match", () => {
      // meta generator (high) + /wp-content/ (medium) + cookie (medium)
      const html =
        '<meta name="generator" content="WordPress 6.5.2"><link href="/wp-content/x.css">';
      const tech = detected("WordPress", {}, html, ["wordpress_logged_in=1"]);

      expect(tech.confidence).toBe("high");
      expect(tech.evidence).toBe("meta generator: WordPress 6.5.2");
    });

    it("falls back to the medium hit when the high one is absent", () => {
      const tech = detected("WordPress", {}, '<link href="/wp-content/x.css">', [
        "wordpress_logged_in=1",
      ]);

      expect(tech.confidence).toBe("medium");
    });

    it("prefers a header hit over a script src hit for the same product", () => {
      const tech = detected("PHP", { "x-powered-by": "PHP/8.2.12" }, "", [
        "PHPSESSID=abc",
      ]);

      expect(tech.confidence).toBe("high");
      expect(tech.evidence).toBe("X-Powered-By: PHP/8.2.12");
      expect(tech.version).toBe("8.2.12");
    });
  });

  describe("version extraction", () => {
    it("looks across headers, cookies and HTML for the version", () => {
      // Matched via the cookie, but the version only appears in a header.
      const tech = detected("PHP", { "x-runtime-note": "built on PHP/8.1.27" }, "", [
        "PHPSESSID=abc",
      ]);

      expect(tech.version).toBe("8.1.27");
    });

    it("tries version patterns in order and takes the first hit", () => {
      // Bootstrap's first pattern is the banner comment, the second the filename.
      const html =
        '<!-- Bootstrap v5.3.3 --><link href="/css/bootstrap.min.css" rel="stylesheet">' +
        '<script src="/js/bootstrap.bundle.min.js"></script>';

      expect(detected("Bootstrap", {}, html).version).toBe("5.3.3");
    });
  });

  it("reports several products from one response", () => {
    const headers: ResponseHeaders = {
      server: "nginx/1.24.0",
      "x-powered-by": "PHP/8.2.12",
    };
    const html =
      '<meta name="generator" content="WordPress 6.5.2">' +
      '<script src="/wp-includes/js/jquery/jquery.min.js"></script>';

    const names = detectTech(headers, html, []).map((t) => t.name);

    expect(names).toContain("nginx");
    expect(names).toContain("PHP");
    expect(names).toContain("WordPress");
    expect(names).toContain("jQuery");
  });
});
