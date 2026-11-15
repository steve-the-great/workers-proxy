export async function onRequest(context) {
  const { request } = context;
  const incomingUrl = new URL(request.url);

  // 1. Check Cloudflare Access header
  const userEmail = request.headers.get("cf-access-authenticated-user-email");
  if (!userEmail) {
    return new Response("Unauthorized - Access Restricted", {
      status: 403,
      headers: { "Content-Type": "text/plain" },
    });
  }

  // 2. Parse the target URL (supports ?url=... OR /https://...)
  const targetParam = incomingUrl.searchParams.get("url") || incomingUrl.pathname.slice(1) + incomingUrl.search;
  if (!targetParam) {
    return new Response("Usage: ?url=https://github.com", {
      status: 400,
      headers: { "Content-Type": "text/plain" },
    });
  }

  let targetUrl;
  try {
    targetUrl = new URL(targetParam);
    if (!["http:", "https:"].includes(targetUrl.protocol)) {
      return new Response("Only HTTP/HTTPS allowed.", { status: 400 });
    }
  } catch {
    return new Response("Invalid target URL provided.", { status: 400 });
  }

  const rewriteToProxy = (rawUrl) => {
    if (!rawUrl || /^(data:|mailto:|tel:|javascript:|#)/i.test(rawUrl)) {
      return rawUrl;
    }
    try {
      const resolved = new URL(rawUrl, targetUrl.href);
      return `${incomingUrl.origin}/?url=${encodeURIComponent(resolved.href)}`;
    } catch {
      return rawUrl;
    }
  };

  // 3. Forward request & strip Cloudflare headers
  const proxyHeaders = new Headers(request.headers);
  for (const key of proxyHeaders.keys()) {
    if (key.startsWith("cf-") || key.startsWith("x-forwarded-")) {
      proxyHeaders.delete(key);
    }
  }
  proxyHeaders.set("Host", targetUrl.host);
  proxyHeaders.set("Origin", targetUrl.origin);
  proxyHeaders.set("Referer", targetUrl.href);

  const response = await fetch(targetUrl.href, {
    method: request.method,
    headers: proxyHeaders,
    body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
    redirect: "manual",
  });

  const newHeaders = new Headers(response.headers);
  newHeaders.delete("content-security-policy");
  newHeaders.delete("content-security-policy-report-only");
  newHeaders.delete("x-frame-options");
  newHeaders.set("Access-Control-Allow-Origin", "*");

  // 4. Handle redirects
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    const location = newHeaders.get("Location");
    if (location) newHeaders.set("Location", rewriteToProxy(location));
    return new Response(null, { status: response.status, headers: newHeaders });
  }

  // 5. Rewrite HTML links and assets
  const contentType = newHeaders.get("content-type") || "";
  if (contentType.includes("text/html")) {
    newHeaders.delete("content-length");

    return new HTMLRewriter()
      .on("a[href], link[href], area[href]", {
        element(el) {
          el.setAttribute("href", rewriteToProxy(el.getAttribute("href")));
        },
      })
      .on("script[src], img[src], iframe[src], video[src], audio[src], source[src]", {
        element(el) {
          el.setAttribute("src", rewriteToProxy(el.getAttribute("src")));
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

  return new Response(response.body, { status: response.status, headers: newHeaders });
}
