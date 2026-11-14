export default {
  async fetch(request, env) {
    const incomingUrl = new URL(request.url);

    // Action 1: Check if the user is verified with a valid, allowed email
    const userEmail = request.headers.get("cf-access-authenticated-user-email");
    const allowedEmail = env.ALLOWED_EMAIL; 

    if (!userEmail || userEmail.toLowerCase() !== allowedEmail.toLowerCase()) {
      return new Response("Unauthorized - Access Restricted", {
        status: 403,
        headers: { "Content-Type": "text/plain" }
      });
    }

    // 2: Parses the URL to proxy.
    const targetParam = incomingUrl.searchParams.get("url");
    if (!targetParam) {
      return new Response(
        "Usage: ?url=https://github.com",
        { status: 400, headers: { "Content-Type": "text/plain" } }
      );
    }

    let targetUrl;
    try {
      targetUrl = new URL(targetParam);
    } catch {
      return new Response("Invalid target URL provided.", { status: 400 });
    }

    // 3: Block Non-HTTP/HTTPS traffic requests
    const rewriteToProxy = (rawUrl) => {
      if (
        !rawUrl ||
        rawUrl.startsWith("data:") ||
        rawUrl.startsWith("mailto:") ||
        rawUrl.startsWith("tel:") ||
        rawUrl.startsWith("javascript:") ||
        rawUrl.startsWith("#")
      ) {
        return rawUrl;
      }

      try {
        // Resolves relative paths to the proxied domain
        const resolved = new URL(rawUrl, targetUrl.href);
        return `${incomingUrl.origin}/?url=${encodeURIComponent(resolved.href)}`;
      } catch {
        return rawUrl;
      }
    };

    // 4: Forward the request to the target site
    const proxyHeaders = new Headers(request.headers);
    proxyHeaders.set("Host", targetUrl.host);
    proxyHeaders.set("Origin", targetUrl.origin);
    proxyHeaders.set("Referer", targetUrl.href);
    
    // 5: Once proxied, remove Cloudflare's headers.
    proxyHeaders.delete("cf-access-authenticated-user-email");
    proxyHeaders.delete("cf-access-jwt-assertion");
    proxyHeaders.delete("cf-connecting-ip");
    proxyHeaders.delete("cf-ray");
    proxyHeaders.delete("cf-visitor");

    const response = await fetch(targetUrl.href, {
      method: request.method,
      headers: proxyHeaders,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : null,
      redirect: "manual", // Manually handles redirects, so the browser still uses the proxy instead of visiting the target domain.
    });

    const newHeaders = new Headers(response.headers);
    newHeaders.delete("content-security-policy");
    newHeaders.delete("content-security-policy-report-only");
    newHeaders.delete("x-frame-options");
    newHeaders.set("Access-Control-Allow-Origin", "*");

    // 6: Handle redirect requests
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = newHeaders.get("Location");
      if (location) {
        newHeaders.set("Location", rewriteToProxy(location));
      }
      return new Response(null, { status: response.status, headers: newHeaders });
    }

    // 7: Rewrite links and forms
    const contentType = newHeaders.get("content-type") || "";
    if (contentType.includes("text/html")) {
      newHeaders.delete("content-length");

        // Function to help rewrite the HTML Document.
      return new HTMLRewriter()
        .on("a[href], link[href], area[href]", {
          element(el) {
            el.setAttribute("href", rewriteToProxy(el.getAttribute("href")));
          },
        })
        .on("script[src], img[src], iframe[src], video[src], audio[src], source[src]", {
          element(el) {
            el.setAttribute("src", rewriteToProxy(el.setAttribute("src")));
          },
        })
        .on("form[action]", {
          element(el) {
            el.setAttribute("action", rewriteToProxy(el.getAttribute("action")));
          },
        })
        .transform(
          new Response(response.body, {
            status: response.status,
            headers: newHeaders,
          })
        );
    }

    // 8: Provide assets directly. (Images, Videos, JS, CSS, etc.)
    return new Response(response.body, { status: response.status, headers: newHeaders });
  },
};
