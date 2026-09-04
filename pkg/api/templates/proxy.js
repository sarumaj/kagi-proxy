// proxy.js
(function () {
  /*
   * Constants
   */

  // proxyToken is the token used to authenticate requests to the proxy
  const proxyToken = `{{ .proxy_token }}`;
  if (!proxyToken || proxyToken.length === 0) {
    throw new Error("proxyToken is empty");
  }
  if (typeof proxyToken !== "string") {
    throw new Error("proxyToken is not a string");
  }

  // hostMap is a map of target hosts to their corresponding proxy domains
  const hostMap = JSON.parse(`{{ .host_map | json }}`);
  if (Object.keys(hostMap).length === 0) {
    throw new Error("hostMap is empty");
  }
  if (
    !Object.entries(hostMap).every(
      ([targetHost, proxyDomain]) =>
        typeof targetHost === "string" &&
        targetHost.length > 0 &&
        typeof proxyDomain === "string" &&
        proxyDomain.length > 0
    )
  ) {
    throw new Error("hostMap contains invalid entries");
  }

  // forbiddenPaths is a list of regular expressions that match URLs
  // that should be disabled in the document
  const forbiddenPaths = JSON.parse(`{{ .forbidden_paths | json }}`);
  if (!Array.isArray(forbiddenPaths)) {
    throw new Error("forbiddenPaths is not an array");
  }
  if (!forbiddenPaths.every((path) => typeof path === "string")) {
    throw new Error("forbiddenPaths contains non-string values");
  }

  // forbiddenElements is a list of CSS selectors that match elements
  // that should be disabled in the document
  const forbiddenElements = JSON.parse(`{{ .forbidden_elements | json }}`);
  if (!Array.isArray(forbiddenElements)) {
    throw new Error("forbiddenElements is not an array");
  }
  if (!forbiddenElements.every((element) => typeof element === "string")) {
    throw new Error("forbiddenElements contains non-string values");
  }

  // retryConfig is the configuration for the retry mechanism
  const retryConfig = JSON.parse(`{{ .retry_config | json }}`);
  if (!typeof retryConfig === "object") {
    throw new Error("retryConfig is not an object");
  }

  // validStatusCodes is a set of valid HTTP status codes for retrying
  const validStatusCodes = new Set([
    // 4xx Client Error
    400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
    415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451,
    // 5xx Server Error
    500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511,
  ]);

  // Validate retry configuration
  // retryCodes is an array of status codes that should be retried
  const retryCodes =
    retryConfig.retry_codes &&
    Array.isArray(retryConfig.retry_codes) &&
    retryConfig.retry_codes.length > 0 &&
    retryConfig.retry_codes.every(
      (code) =>
        typeof code === "number" &&
        Number.isInteger(code) &&
        validStatusCodes.has(code)
    )
      ? retryConfig.retry_codes
      : [];

  // maxRetries is the maximum number of retries for a request
  const maxRetries =
    retryConfig.max_retries &&
    typeof retryConfig.max_retries === "number" &&
    retryConfig.max_retries >= 0 &&
    Number.isInteger(retryConfig.max_retries)
      ? retryConfig.max_retries
      : 0;

  // retryDelay is the delay between retries in milliseconds
  const retryDelay =
    retryConfig.retry_delay &&
    typeof retryConfig.retry_delay === "number" &&
    retryConfig.retry_delay >= 0
      ? retryConfig.retry_delay
      : 0;

  // proxyUser is the account the proxy authenticated the visitor as. The banner names it so
  // that a proxied tab is recognisable as such, and so is the session that gets signed out.
  const proxyUser = JSON.parse(`{{ .proxy_user | json }}`) || "";

  // signOutURL ends the proxy session. It is the proxy's own route rather than the target
  // host's: signing out here must not terminate the shared subscription session.
  const signOutURL = JSON.parse(`{{ .signout_url | json }}`);

  // privateThreads mirrors the proxy's thread isolation setting.
  const privateThreads = JSON.parse(`{{ .private_threads | json }}`) === true;

  // threadPathPattern matches the assistant routes that open a single thread. The proxy
  // authorizes the very same pattern; here it identifies the rows to hide and the
  // client-side navigation that means a thread has just been created.
  const threadPathPattern = new RegExp(JSON.parse(`{{ .thread_pattern | json }}`));

  // threadClaimURL is the proxy route a thread created in this tab is reported to.
  const threadClaimURL = JSON.parse(`{{ .thread_claim_url | json }}`);

  // ownedThreads are the threads this session is allowed to see. They all live in the one
  // account behind the proxy, so the assistant lists everybody's threads and the ones that
  // are not in this set get hidden.
  const ownedThreads = new Set(
    (JSON.parse(`{{ .owned_threads | json }}`) || []).map((id) =>
      String(id).toLowerCase()
    )
  );

  // bannerId is the id of the proxy's own badge, which is excluded from every rewrite.
  const bannerId = "kagi-proxy-banner";

  // bannerCollapsedKey remembers, per tab, whether the badge was collapsed to its icon.
  const bannerCollapsedKey = "kagi-proxy-banner-collapsed";

  /*
   * Utility functions
   */

  // isBannerCollapsed and setBannerCollapsed persist the badge state for the tab. Reading
  // and writing storage throws rather than returning null where the browser blocks site
  // data, so a failure degrades to the expanded badge.
  const isBannerCollapsed = () => {
    try {
      return window.sessionStorage.getItem(bannerCollapsedKey) === "1";
    } catch (e) {
      console.debug("Banner state not readable:", e);
      return false;
    }
  };

  const setBannerCollapsed = (collapsed) => {
    try {
      window.sessionStorage.setItem(bannerCollapsedKey, collapsed ? "1" : "0");
    } catch (e) {
      console.debug("Banner state not persisted:", e);
    }
  };

  // mountBanner pins a badge to the page stating that the site is being proxied and
  // offering a way out of the proxy session. It is idempotent, so it can be called again
  // whenever the application replaces the document body.
  //
  // Every style is assigned through the CSSOM instead of a stylesheet or a style
  // attribute: the target host serves a Content-Security-Policy that does not allow inline
  // styles, and property assignment is the one route it does not block.
  const mountBanner = () => {
    if (!document.body || document.getElementById(bannerId)) return;

    const banner = document.createElement("div");
    banner.id = bannerId;
    banner.setAttribute("role", "status");
    Object.assign(banner.style, {
      alignItems: "center",
      background: "rgba(20, 20, 22, 0.92)",
      border: "1px solid rgba(255, 255, 255, 0.18)",
      borderRadius: "999px",
      bottom: "12px",
      boxShadow: "0 2px 12px rgba(0, 0, 0, 0.35)",
      color: "#f2f2f2",
      display: "flex",
      font: '500 12px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
      gap: "8px",
      padding: "6px 10px",
      position: "fixed",
      right: "12px",
      zIndex: "2147483647",
    });

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.textContent = "\u{1F6E1}";
    toggle.title = "Show or hide the proxy banner";
    toggle.setAttribute("aria-label", toggle.title);
    Object.assign(toggle.style, {
      background: "none",
      border: "none",
      color: "inherit",
      cursor: "pointer",
      font: "inherit",
      lineHeight: "1",
      padding: "0",
    });

    const label = document.createElement("span");
    label.textContent = proxyUser.length > 0 ? "Proxied \u00b7 " + proxyUser : "Proxied";

    const signOut = document.createElement("button");
    signOut.type = "button";
    signOut.textContent = "Sign out";
    signOut.title = "End the proxy session";
    Object.assign(signOut.style, {
      background: "rgba(255, 255, 255, 0.12)",
      border: "1px solid rgba(255, 255, 255, 0.25)",
      borderRadius: "999px",
      color: "inherit",
      cursor: "pointer",
      font: "inherit",
      padding: "2px 8px",
      whiteSpace: "nowrap",
    });
    signOut.addEventListener("click", () => window.location.assign(signOutURL));

    const render = () => {
      const collapsed = isBannerCollapsed();
      label.style.display = collapsed ? "none" : "";
      signOut.style.display = collapsed ? "none" : "";
      banner.style.opacity = collapsed ? "0.6" : "1";
      banner.title = collapsed ? "Proxied session" : "";
    };

    toggle.addEventListener("click", () => {
      setBannerCollapsed(!isBannerCollapsed());
      render();
    });

    banner.append(toggle, label, signOut);
    document.body.appendChild(banner);
    render();
  };

  // threadIdFromPath returns the thread a path opens, or null if it opens none.
  const threadIdFromPath = (path) => {
    const match = threadPathPattern.exec(path || "");
    return match ? match[1].toLowerCase() : null;
  };

  // applyThreadVisibility hides the list row of a thread this session does not own. The
  // hiding is cosmetic: the proxy denies the request for a foreign thread either way, and
  // this only keeps the sidebar from filling up with links that lead to the error page.
  const applyThreadVisibility = (anchor) => {
    if (!privateThreads) return;

    let path;
    try {
      path = new URL(anchor.getAttribute("href"), window.location.href).pathname;
    } catch (e) {
      console.debug("Thread URL parsing failed:", e);
      return;
    }

    const threadId = threadIdFromPath(path);
    if (!threadId) return;

    const row = anchor.closest('li, [role="listitem"]') || anchor;
    if (ownedThreads.has(threadId)) {
      row.style.removeProperty("display");
      return;
    }

    row.style.display = "none";
  };

  // replaceHost function replaces the host of the given URL with the proxy domain
  // and appends the proxy token if the original URL contains a token
  const replaceHost = (url) => {
    if (!url) return url;
    try {
      const urlObj = new URL(url, window.location.href);
      if (!["http:", "https:", "ws:", "wss:"].includes(urlObj.protocol)) {
        return url;
      }

      // Check if the URL contains a token and replace it with the proxy token
      const tokenValue = urlObj.searchParams.get("token");
      if (tokenValue && tokenValue.length > 0) {
        urlObj.searchParams.delete("token");
        if (proxyToken && proxyToken.length > 0) {
          urlObj.searchParams.set("proxy_token", proxyToken);
        }
      }

      // Replace the host with the proxy domain
      for (const [targetHost, proxyDomain] of Object.entries(hostMap)) {
        if (
          urlObj.host === targetHost ||
          urlObj.host.endsWith("." + targetHost)
        ) {
          urlObj.host = urlObj.host.replace(targetHost, proxyDomain);
          return urlObj.toString();
        }
      }
    } catch (e) {
      console.debug("URL parsing failed:", e);
    }
    return url;
  };

  // replaceJavaScriptURL function replaces URLs in JavaScript code
  // to point to the proxy domain
  const replaceJavaScriptURL = (jsURL) => {
    try {
      // Remove 'javascript:' prefix
      const code = jsURL.replace(/^javascript:/, "");
      let modifiedCode = code;

      // Replace URLs in string literals
      modifiedCode = modifiedCode.replace(
        /(["'])(https?:\/\/[^"']+)\1/g,
        (match, quote, url) => quote + replaceHost(url) + quote
      );

      // Handle template literals
      modifiedCode = modifiedCode.replace(/`([^`]*)`/g, (match, content) => {
        return (
          "`" +
          content.replace(/(https?:\/\/[^`$]+)/g, (url) => replaceHost(url)) +
          "`"
        );
      });

      return "javascript:" + modifiedCode;
    } catch (e) {
      console.debug("JavaScript URL processing failed:", e);
      return jsURL;
    }
  };

  // processNode function replaces URLs
  const processNode = (node) => {
    if (!(node instanceof Element)) return;

    // The banner belongs to the proxy rather than to the page, so it is exempt from the
    // rewriting and from the rules that disable elements.
    if (node.id === bannerId || (node.closest && node.closest("#" + bannerId))) return;

    const patterns = forbiddenPaths.map((path) => new RegExp(path));
    const disableElement = (element) => {
      element.style.opacity = "0.6";
      element.style.pointerEvents = "none";
      element.style.cursor = "not-allowed";
      element.disabled = true;
    };

    // Handle attributes for proxy logic
    if (node.nodeType === Node.ELEMENT_NODE) {
      for (const selector of forbiddenElements) {
        if (node.matches(selector)) {
          disableElement(node);
          break;
        }
      }

      const attributes = ["href", "src", "action", "data-url"];
      for (const attr of attributes) {
        if (!node.hasAttribute(attr)) continue;

        const attrValue = node.getAttribute(attr);

        const newValue = attrValue.startsWith("javascript:")
          ? replaceJavaScriptURL(attrValue)
          : replaceHost(attrValue);

        if (newValue !== attrValue) {
          node.setAttribute(attr, newValue);
        }

        if (patterns.some((pattern) => pattern.test(attrValue))) {
          disableElement(node);
          continue;
        }
      }

      if (node.tagName === "A" && node.hasAttribute("href")) {
        applyThreadVisibility(node);
      }
    }

    // Handle inline scripts
    if (node.tagName === "SCRIPT" && !node.src) {
      const originalText = node.textContent;
      let modifiedText = originalText;

      // Replace URLs in string literals
      modifiedText = modifiedText.replace(
        /(["'])(https?:\/\/[^"']+)\1/g,
        (match, quote, url) => quote + replaceHost(url) + quote
      );

      // Handle template literals
      modifiedText = modifiedText.replace(/`([^`]*)`/g, (match, content) => {
        return (
          "`" +
          content.replace(/(https?:\/\/[^`$]+)/g, (url) => replaceHost(url)) +
          "`"
        );
      });

      if (modifiedText !== originalText) {
        const newScript = document.createElement("script");
        newScript.textContent = modifiedText;
        node.parentNode.replaceChild(newScript, node);
      }
    }
  };

  /*
   * Main logic
   */

  // Create a MutationObserver to handle dynamically added content
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          processNode(node);
          try {
            const elements = node.querySelectorAll("*");
            elements.forEach(processNode);
          } catch (e) {
            console.debug("Error processing node children:", e);
          }
        }
      });
    });

    // The application owns the body and re-creates it on navigation, which takes the
    // banner with it.
    mountBanner();
  });

  // Process existing content
  const processExistingContent = () => {
    try {
      const elements = document.querySelectorAll("*");
      elements.forEach(processNode);
    } catch (e) {
      console.debug("Error processing existing content:", e);
    }

    mountBanner();
  };

  // Wait for DOM to be ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      processExistingContent();
      // Observe future changes
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
      });
    });
  } else {
    processExistingContent();
    // Observe future changes
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  // Handle dynamic XHR/Fetch requests
  const originalFetch = window.fetch;
  window.fetch = async function (input, init) {
    // Store the original body if present
    let bodyBuffer = null;
    if (init?.body) {
      bodyBuffer = init.body;
    }

    let url = typeof input === "string" ? input : input.url;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        // Reset body for each attempt if it exists
        if (bodyBuffer) {
          init = { ...init, body: bodyBuffer };
        }

        // Process URL and create request
        let processedInput;
        if (typeof input === "string") {
          processedInput = replaceHost(input);
        } else if (input instanceof Request) {
          processedInput = new Request(replaceHost(input.url), input);
        }

        const response = await originalFetch.call(this, processedInput, init);

        // Handle specific status codes
        if (retryCodes.includes(response.status)) {
          console.warn(
            `Retryable status code ${response.status}, retrying request`,
            {
              url,
              attempt,
              status: response.status,
            }
          );

          // Wait before retry with exponential backoff
          await new Promise((resolve) =>
            setTimeout(resolve, retryDelay * (attempt + 1))
          );
          continue;
        }

        return response;
      } catch (error) {
        if (attempt === maxRetries) {
          throw error;
        }

        console.warn("Network error, retrying request", {
          url,
          attempt,
          error,
        });

        await new Promise((resolve) =>
          setTimeout(resolve, retryDelay * (attempt + 1))
        );
      }
    }
  };

  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url, ...args) {
    this._retryConfig = {
      maxRetries: maxRetries,
      retryDelay: retryDelay,
      attempt: 0,
      originalUrl: url,
      originalMethod: method,
      originalArgs: args,
    };
    url = replaceHost(url);
    return originalXHROpen.call(this, method, url, ...args);
  };

  XMLHttpRequest.prototype.send = function (body) {
    // Store original callbacks
    const originalOnload = this.onload;
    const originalOnerror = this.onerror;
    const originalBody = body;

    const retry = () => {
      this._retryConfig.attempt++;
      const delay = this._retryConfig.retryDelay * this._retryConfig.attempt;

      console.warn(`Retrying XHR request`, {
        url: this._retryConfig.originalUrl,
        attempt: this._retryConfig.attempt,
      });

      setTimeout(() => {
        // Reopen connection
        originalXHROpen.call(
          this,
          this._retryConfig.originalMethod,
          replaceHost(this._retryConfig.originalUrl),
          ...this._retryConfig.originalArgs
        );
        // Resend with original body
        originalXHRSend.call(this, originalBody);
      }, delay);
    };

    this.onload = (e) => {
      if (retryCodes.includes(this.status)) {
        if (this._retryConfig.attempt < this._retryConfig.maxRetries) {
          retry();
          return;
        }
      }

      // Call original onload if exists
      if (originalOnload) {
        originalOnload.call(this, e);
      }
    };

    this.onerror = (e) => {
      if (this._retryConfig.attempt < this._retryConfig.maxRetries) {
        retry();
        return;
      }
      // Call original onerror if exists
      if (originalOnerror) {
        originalOnerror.call(this, e);
      }
    };

    return originalXHRSend.call(this, body);
  };

  // Handle WebSocket connections since kagi uses them
  const originalWebSocket = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    // WebSockets are cross-domain by default, still needed to proxy the URL
    url = replaceHost(url);
    return new originalWebSocket(url, protocols);
  };

  // originalHistory keeps the navigation methods the thread watcher wraps.
  const originalHistory = {};

  // claimThread tells the proxy that the thread the tab has just navigated to belongs to
  // this session.
  //
  // The assistant creates a thread client side and only swaps the new URL in with
  // history.pushState, so no request for it ever reaches the proxy. Without this report the
  // proxy would not learn the id until the page is loaded again, and until then the thread
  // the user is writing in would count as somebody else's and be hidden. A claim is refused
  // for a thread another session already holds, so reporting one is not a way to reach it.
  const claimThread = async (threadId) => {
    if (!privateThreads || !threadId || ownedThreads.has(threadId)) return;

    // Take ownership locally first, so that the row of the new thread is not hidden for as
    // long as the request is in flight.
    ownedThreads.add(threadId);

    try {
      const response = await originalFetch.call(window, threadClaimURL, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ thread_id: threadId }),
      });

      if (!response.ok) {
        ownedThreads.delete(threadId);
        console.debug("Thread claim rejected:", response.status);
      } else {
        const payload = await response.json();
        (payload.threads || []).forEach((id) =>
          ownedThreads.add(String(id).toLowerCase())
        );
      }
    } catch (e) {
      ownedThreads.delete(threadId);
      console.debug("Thread claim failed:", e);
    }

    processExistingContent();
  };

  // Watch the client-side navigation for the thread the tab is in.
  const watchThreadNavigation = () => {
    if (!privateThreads) return;

    const claimCurrent = () => claimThread(threadIdFromPath(window.location.pathname));

    for (const method of ["pushState", "replaceState"]) {
      originalHistory[method] = history[method];
      history[method] = function (...args) {
        const result = originalHistory[method].apply(this, args);
        claimCurrent();
        return result;
      };
    }

    window.addEventListener("popstate", claimCurrent);
    claimCurrent();
  };

  watchThreadNavigation();

  const cleanup = () => {
    observer.disconnect();
    window.fetch = originalFetch;
    window.WebSocket = originalWebSocket;
    XMLHttpRequest.prototype.open = originalXHROpen;
    XMLHttpRequest.prototype.send = originalXHRSend;
    for (const method of Object.keys(originalHistory)) {
      history[method] = originalHistory[method];
    }
  };

  window.addEventListener("unload", cleanup);
})();
