/**
 * VULNERABLE APPLICATION DISCLAIMER
 * Bottom sheet warning for security training environment
 */

(function () {
  "use strict";

  const DISCLAIMER_KEY = "mybankgweh_disclaimer_acknowledged";

  // Automatically acknowledge the disclaimer to hide it on first visit
  if (!localStorage.getItem(DISCLAIMER_KEY)) {
    localStorage.setItem(DISCLAIMER_KEY, "true");
  }

  // Define functions to prevent reference errors
  function createDisclaimer() {
    // Function is defined but not used
  }

  // Global dismiss function
  window.dismissVulnDisclaimer = function () {
    // Function is defined but not used
  };

  // Don't set up event listeners to show disclaimer
  // Since we're automatically acknowledging, no need to create or listen for events
})();
