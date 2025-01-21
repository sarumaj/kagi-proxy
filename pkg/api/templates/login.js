// login.js
document.addEventListener("DOMContentLoaded", function () {
  /*
   * Constants
   */
  const VALIDATION = {
    OTP_LENGTH: 8,
    OTP_PATTERN: /^\d+$/,
    COPY_TIMEOUT: 2000,
  };

  const SVG_PATHS = {
    VISIBLE:
      "M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z",
    HIDDEN:
      "M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z",
  };

  /*
   * Utility functions
   */

  // debounce function to limit the rate of function calls
  const debounce = (fn, delay) => {
    let timeoutId;
    return (...args) => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => fn.apply(this, args), delay);
    };
  };

  // isValidOtpInput checks if the input is a valid OTP code
  const isValidOtpInput = (value) => {
    return (
      typeof value === "string" &&
      value.length === VALIDATION.OTP_LENGTH &&
      VALIDATION.OTP_PATTERN.test(value)
    );
  };

  /*
   * DOM Elements
   */
  const loginForm = document.getElementById("login-form");
  const setupForm = document.getElementById("setup-form");
  const otpInput = document.getElementById("otp");
  const passwordInput = document.getElementById("password");
  const passwordToggleButton = document.querySelector(".password-toggle");
  const secretKeyContainer = document.getElementById("secret-key");
  const copyButton = document.getElementById("copy-secret");
  const otpFields = document.querySelectorAll(".otp-field");
  const otpContainer = document.querySelector(".otp-fields");
  const tabs = document.querySelectorAll(".tab");
  const qrContainer = document.getElementById("qr-container");

  // Validate required elements
  for (const [selector, element] of Object.entries({
    "login-form": loginForm,
    "setup-form": setupForm,
    otp: otpInput,
    password: passwordInput,
    ".password-toggle": passwordToggleButton,
    "secret-key": secretKeyContainer,
    "copy-secret": copyButton,
    ".otp-field": otpFields,
    ".otp-fields": otpContainer,
    ".tab": tabs,
    "qr-container": qrContainer,
  })) {
    if (!element) {
      console.error(`Required element with selector: "${selector}" not found`);
      return;
    }
  }

  // handleLoginSubmit function to validate OTP input
  const handleLoginSubmit = (e) => {
    const otp = otpInput.value;
    if (!isValidOtpInput(otp)) {
      e.preventDefault();
      alert("Please enter a complete 8-digit OTP code");
    }
  };

  // handleToggle function to toggle password visibility
  const handleToggle = () => {
    const type =
      passwordInput.getAttribute("type") === "password" ? "text" : "password";
    passwordInput.setAttribute("type", type);
    const path = passwordToggleButton.querySelector("path");
    path.setAttribute(
      "d",
      type === "password" ? SVG_PATHS.VISIBLE : SVG_PATHS.HIDDEN
    );
  };

  // handleAutocomplete function to handle OTP autofill
  // hidden input field is used to trigger the autofill event
  const handleAutocomplete = (e) => {
    e.preventDefault();
    // Get value either from event target or from the first OTP field
    const value = e.target.value || otpFields[0].value;
    if (isValidOtpInput(value)) {
      const digits = value.split("");
      otpFields.forEach((field, index) => {
        field.value = digits[index] || "";
        field.dispatchEvent(new Event("input", { bubbles: true }));
      });
      otpInput.value = value;
    }
  };

  // debouncedPaste function to handle pasting OTP code
  const debouncedPaste = debounce((pastedData, fields) => {
    if (!VALIDATION.OTP_PATTERN.test(pastedData)) return;

    const digits = pastedData.split("").slice(0, fields.length);
    fields.forEach((field, index) => {
      field.value = digits[index] || "";
      field.dispatchEvent(new Event("input")); // trigger input event
    });

    // Focus on the next empty field
    const nextEmptyField = Array.from(fields).find((field) => !field.value);
    if (nextEmptyField) {
      nextEmptyField.focus();
    } else {
      fields[fields.length - 1].focus();
    }
  }, 100);

  // updateOtpValue function to update the hidden OTP input value
  const updateOtpValue = () => {
    otpInput.value = Array.from(otpFields)
      .map((field) => field.value)
      .join("");
  };

  /*
   * Event Listeners
   */
  loginForm.addEventListener("submit", handleLoginSubmit);
  passwordToggleButton.addEventListener("click", handleToggle);

  // Clicking on the OTP container focuses on the first empty field
  otpContainer.addEventListener("click", () => {
    const emptyField =
      Array.from(otpFields).find((field) => !field.value) || otpFields[0];
    emptyField.focus();
  });

  otpFields.forEach((field, index) => {
    // Register autofill event listeners for OTP fields
    if (field.getAttribute("autocomplete") === "one-time-code") {
      field.addEventListener("webkitAutoFill", handleAutocomplete);
      field.addEventListener("autocompleteerror", handleAutocomplete);
      field.addEventListener("autocomplete", handleAutocomplete);
      field.addEventListener("input", handleAutocomplete);
    }

    // Register input event listeners for OTP fields
    field.addEventListener("input", (e) => {
      const value = e.target.value;
      if (value && !VALIDATION.OTP_PATTERN.test(value)) {
        field.value = "";
        return;
      }
      if (value && index < otpFields.length - 1) {
        otpFields[index + 1].focus();
      }
      updateOtpValue();
    });

    // Register keydown event listeners for OTP fields
    field.addEventListener("keydown", (e) => {
      switch (e.key) {
        case "Backspace":
          if (!field.value && index > 0) {
            otpFields[index - 1].focus();
            otpFields[index - 1].value = "";
            updateOtpValue();
          }
          break;
        case "ArrowLeft":
          if (index > 0) otpFields[index - 1].focus();
          break;
        case "ArrowRight":
          if (index < otpFields.length - 1) otpFields[index + 1].focus();
          break;
        case "Delete":
          field.value = "";
          updateOtpValue();
          break;
      }
    });

    // Register paste event listeners for OTP fields
    field.addEventListener("paste", (e) => {
      e.preventDefault();
      const pastedData = e.clipboardData.getData("text").trim();
      debouncedPaste(pastedData, otpFields);
    });
  });

  // Copy OTP URL to clipboard
  copyButton.addEventListener("click", async () => {
    const secretKey = secretKeyContainer.textContent;
    try {
      await navigator.clipboard.writeText(secretKey);
      copyButton.textContent = "Copied!";
      setTimeout(() => {
        copyButton.textContent = "Copy Secret URL";
      }, VALIDATION.COPY_TIMEOUT);
    } catch (err) {
      console.error("Failed to copy:", err);
      copyButton.textContent = "Failed to copy";
      setTimeout(() => {
        copyButton.textContent = "Copy Secret URL";
      }, VALIDATION.COPY_TIMEOUT);
    }
  });

  // Switch tabs
  tabs.forEach((tab) => {
    tab.addEventListener("click", function (e) {
      e.preventDefault();
      try {
        const tabId = this.getAttribute("data-tab");

        // Update active states
        document.querySelector(".tab.active").classList.remove("active");
        this.classList.add("active");

        document
          .querySelector(".tab-content.active")
          .classList.remove("active");
        document.querySelector(`#${tabId}-tab`).classList.add("active");
      } catch (err) {
        console.error("Failed to switch tabs:", err);
      }
    });
  });

  // Cleanup function
  function cleanup() {
    loginForm.removeEventListener("submit", handleLoginSubmit);
    passwordToggleButton.removeEventListener("click", handleToggle);
    otpContainer.removeEventListener("click", null);
    copyButton.removeEventListener("click", null);

    otpFields.forEach((field) => {
      if (field.getAttribute("autocomplete") === "one-time-code") {
        field.removeEventListener("webkitAutoFill", handleAutocomplete);
        field.removeEventListener("autocompleteerror", handleAutocomplete);
        field.removeEventListener("autocomplete", handleAutocomplete);
        field.removeEventListener("input", handleAutocomplete);
      }
      field.removeEventListener("input", null);
      field.removeEventListener("keydown", null);
      field.removeEventListener("paste", null);
    });

    tabs.forEach((tab) => {
      tab.removeEventListener("click", null);
    });
  }

  // Cleanup on unload
  window.addEventListener("unload", cleanup);
});
