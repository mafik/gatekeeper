function AutorefreshChecked() {
  return document.getElementById("autorefresh").checked;
}

// Note: Gatekeeper uses `morphdom` becasue the most recent version of htmx (1.9.2)
// does not include the built-in `idiomorph` yet. This is planned for htmx-2.
// Once htmx updates, `morphdom` can be removed.
// https://unpkg.com/htmx.org@1.9.2/dist/ext/morphdom-swap.js
htmx.defineExtension('morphdom-swap', {
  isInlineSwap: function (swapStyle) {
    return swapStyle === 'morphdom';
  },
  handleSwap: function (swapStyle, target, fragment) {
    if (swapStyle === 'morphdom') {
      console.log("morphdom swap", target, fragment);
      if (fragment.nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
        morphdom(target, fragment.firstElementChild);
        return [target];
      } else {
        morphdom(target, fragment.outerHTML);
        return [target];
      }
    }
  }
});