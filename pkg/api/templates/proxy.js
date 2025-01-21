// proxy.js
(function () {
  const proxyToken = `{{ .proxy_token }}`;
  const originalHostMap = JSON.parse(`{{ json .host_map }}`);
  const hostMap = Object.fromEntries(
    Object.entries(originalHostMap).map(([proxy, target]) => [target, proxy])
  );

  // Make sure the logEvent function is defined when running in proxy mode
  window.logEvent =
    window.logEvent ||
    function () {
      console.debug("Logging disabled in proxy mode");
    };

  // replaceHost function replaces the host of the given URL with the proxy domain
  // and appends the proxy token if the original URL contains a token
  const replaceHost = (url) => {
    if (!url) return url;
    try {
      const urlObj = new URL(url, window.location.href);
      const tokenValue = urlObj.searchParams.get("token");
      if (tokenValue && tokenValue.length > 0) {
        urlObj.searchParams.delete("token");
        if (proxyToken && proxyToken.length > 0) {
          urlObj.searchParams.set("proxy_token", proxyToken);
        }
      }
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
  const processNode = (node) => {
    // Handle attributes
    if (node.nodeType === Node.ELEMENT_NODE) {
      ["href", "src", "action", "data-url"].forEach((attr) => {
        if (node.hasAttribute(attr)) {
          const attrValue = node.getAttribute(attr);
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
  window.fetch = function (input, init) {
    if (typeof input === "string") {
      input = replaceHost(input);
    } else if (input instanceof Request) {
      input = new Request(replaceHost(input.url), input);
    }
    return originalFetch.call(this, input, init);
  };

  const originalXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...args) {
    url = replaceHost(url);
    return originalXHROpen.call(this, method, url, ...args);
  };

  // Handle WebSocket connections since kagi uses them
  const originalWebSocket = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    // WebSockets are cross-domain by default, still needed to proxy the URL
    url = replaceHost(url);
    return new originalWebSocket(url, protocols);
  };
})();
