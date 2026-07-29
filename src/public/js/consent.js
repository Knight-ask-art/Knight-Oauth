"use strict";

document.querySelectorAll("[data-consent-client-logo]").forEach((image) => {
  const revealFallback = () => {
    image.hidden = true;
  };

  image.addEventListener("error", revealFallback, { once: true });
  if (image.complete && image.naturalWidth === 0) revealFallback();
});
