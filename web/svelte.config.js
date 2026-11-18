// Svelte compiler options. Component CSS goes to the CSS file, not to
// <style> elements at run time, so a strict CSP (style-src 'self') works.
export default {
  compilerOptions: {
    css: 'external',
  },
};
