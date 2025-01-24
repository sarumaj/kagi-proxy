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
  if (forbiddenPaths.length === 0) {
    throw new Error("forbiddenPaths is empty");
  }
  if (!forbiddenPaths.every((path) => typeof path === "string")) {
    throw new Error("forbiddenPaths contains non-string values");
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

  /*
   * Utility functions
   */

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

  // processNode function replaces URLs in the given DOM node
  // and its children
  // It also hides certain elements in the settings page
  const processNode = (node) => {
    if (!(node instanceof Element)) return;

    const patterns = forbiddenPaths.map((path) => new RegExp(path));

    // Handle attributes
    if (node.nodeType === Node.ELEMENT_NODE) {
      ["href", "src", "action", "data-url"].forEach((attr) => {
        if (node.hasAttribute(attr)) {
          const attrValue = node.getAttribute(attr);

          patterns.forEach((pattern) => {
            if (pattern.test(attrValue)) {
              node.style.opacity = "0.6";
              node.style.pointerEvents = "none";
              node.style.cursor = "not-allowed";
              node.disabled = true;
            }
          });

          let newValue = attrValue;

          // Handle javascript: URLs
          if (attrValue.startsWith("javascript:")) {
            newValue = replaceJavaScriptURL(attrValue);
          } else {
            newValue = replaceHost(attrValue);
          }

          if (newValue !== attrValue) {
            node.setAttribute(attr, newValue);
          }
        }
      });
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
          node.querySelectorAll("*").forEach(processNode);
        }
      });
    });
  });

  // Process existing content
  document.querySelectorAll("*").forEach(processNode);

  // Observe future changes
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });

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

  const cleanup = () => {
    observer.disconnect();
    window.fetch = originalFetch;
    window.WebSocket = originalWebSocket;
    XMLHttpRequest.prototype.open = originalXHROpen;
    XMLHttpRequest.prototype.send = originalXHRSend;
  };

  window.addEventListener("unload", cleanup);
})();
