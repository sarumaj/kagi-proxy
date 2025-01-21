// proxy.js
(function () {
  const originalHostMap = JSON.parse(`{{ json .host_map }}`);
  const hostMap = Object.fromEntries(
    Object.entries(originalHostMap).map(([proxy, target]) => [target, proxy])
  );

  window.logEvent =
    window.logEvent ||
    function () {
      console.debug("Logging disabled in proxy mode");
    };

  function replaceHost(url) {
    if (!url) return url;
    try {
      const urlObj = new URL(url, window.location.href);
      const tokenValue = urlObj.searchParams.get("token");
      if (tokenValue && tokenValue.length > 0) {
        urlObj.searchParams.delete("token");
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
  }

  function processNode(node) {
    // Handle attributes
    if (node.nodeType === Node.ELEMENT_NODE) {
      ["href", "src", "action", "data-url"].forEach((attr) => {
        if (node.hasAttribute(attr)) {
          const newValue = replaceHost(node.getAttribute(attr));
          if (newValue !== node.getAttribute(attr)) {
            node.setAttribute(attr, newValue);
          }
        }
      });
    }

    // Handle inline scripts
    if (node.tagName === "SCRIPT" && !node.src) {
      const originalText = node.textContent;
      let modifiedText = originalText;
      for (const [targetHost, proxyDomain] of Object.entries(hostMap)) {
        const regex = new RegExp(
          targetHost.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
          "g"
        );
        modifiedText = modifiedText.replace(regex, proxyDomain);
      }
      if (modifiedText !== originalText) {
        const newScript = document.createElement("script");
        newScript.textContent = modifiedText;
        node.parentNode.replaceChild(newScript, node);
      }
    }
  }

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

  // Handle WebSocket connections
  const originalWebSocket = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    url = replaceHost(url);
    return new originalWebSocket(url, protocols);
  };
})();
