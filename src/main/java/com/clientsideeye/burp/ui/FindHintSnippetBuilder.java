package com.clientsideeye.burp.ui;

final class FindHintSnippetBuilder {
    private FindHintSnippetBuilder() {
    }

    static String locateSnippet(String selector) {
        String jsSelector = FindHintBuilder.jsSingleQuoteEscape(selector);
        return """
            (() => {
              const matches = [...document.querySelectorAll('__SELECTOR__')];
              if (!matches.length) return console.log('[ClientSideEye] no matches for selector:', '__SELECTOR__');
              matches.forEach((el, i) => {
                el.scrollIntoView({block:'center'});
                console.log('[ClientSideEye] match', i, el);
              });
              if (matches[0] && typeof inspect === 'function') inspect(matches[0]);
              return matches;
            })()
            """.replace("__SELECTOR__", jsSelector).trim();
    }

    static String locateByTextSnippet(FindHintEvidence evidence) {
        String jsText = FindHintBuilder.jsSingleQuoteEscape(evidence.text);
        String jsRole = FindHintBuilder.jsSingleQuoteEscape(evidence.role);
        String jsType = FindHintBuilder.jsSingleQuoteEscape(evidence.type);
        return """
            (() => {
              const want = '__TEXT__'.trim().toLowerCase();
              const nodes = [...document.querySelectorAll('button,a,input,select,textarea,[role="button"],[role]')];
              const matches = nodes.filter(el => {
                const textValue = (el.innerText || el.textContent || el.value || '').replace(/\s+/g, ' ').trim().toLowerCase();
                if (want && textValue !== want) return false;
                if ('__ROLE__' && el.getAttribute('role') !== '__ROLE__') return false;
                if ('__TYPE__' && (el.getAttribute('type') || '').toLowerCase() !== '__TYPE__') return false;
                return true;
              });
              matches.forEach((el, i) => console.log('[ClientSideEye] text match', i, el));
              if (matches[0]) { matches[0].scrollIntoView({block:'center'}); if (typeof inspect === 'function') inspect(matches[0]); }
              return matches;
            })()
            """
            .replace("__TEXT__", jsText)
            .replace("__ROLE__", jsRole)
            .replace("__TYPE__", jsType)
            .trim();
    }

    static String deepLocateSnippet(String selector, FindHintEvidence evidence) {
        String jsSelector = FindHintBuilder.jsSingleQuoteEscape(selector == null ? "" : selector);
        String jsText = FindHintBuilder.jsSingleQuoteEscape(evidence.text == null ? "" : evidence.text);
        String jsRole = FindHintBuilder.jsSingleQuoteEscape(evidence.role == null ? "" : evidence.role);
        String jsType = FindHintBuilder.jsSingleQuoteEscape(evidence.type == null ? "" : evidence.type);
        return """
            (() => {
              const selector = '__SELECTOR__';
              const wantText = '__TEXT__'.trim().toLowerCase();
              const seen = new Set();
              const roots = [document];
              [...document.querySelectorAll('*')].forEach(el => { if (el.shadowRoot) roots.push(el.shadowRoot); });
              [...document.querySelectorAll('iframe')].forEach(frame => { try { if (frame.contentDocument) roots.push(frame.contentDocument); } catch (e) {} });
              const matches = [];
              const add = el => { if (el && !seen.has(el)) { seen.add(el); matches.push(el); } };
              roots.forEach(root => {
                try {
                  if (selector) root.querySelectorAll(selector).forEach(add);
                  if (!matches.length && wantText) {
                    root.querySelectorAll('button,a,input,select,textarea,[role],[role="button"]').forEach(el => {
                      const textValue = (el.innerText || el.textContent || el.value || '').replace(/\s+/g, ' ').trim().toLowerCase();
                      if (textValue !== wantText) return;
                      if ('__ROLE__' && el.getAttribute('role') !== '__ROLE__') return;
                      if ('__TYPE__' && (el.getAttribute('type') || '').toLowerCase() !== '__TYPE__') return;
                      add(el);
                    });
                  }
                } catch (e) {}
              });
              matches.forEach((el, i) => console.log('[ClientSideEye] deep match', i, el));
              if (matches[0]) { matches[0].scrollIntoView({block:'center'}); if (typeof inspect === 'function') inspect(matches[0]); }
              return matches;
            })()
            """
            .replace("__SELECTOR__", jsSelector)
            .replace("__TEXT__", jsText)
            .replace("__ROLE__", jsRole)
            .replace("__TYPE__", jsType)
            .trim();
    }

    static String highlightSnippet(String selector, FindHintEvidence evidence) {
        String baseLocate = !selector.isBlank() ? "root.querySelectorAll('" + FindHintBuilder.jsSingleQuoteEscape(selector) + "').forEach(add);" : "";
        String jsText = FindHintBuilder.jsSingleQuoteEscape(evidence.text == null ? "" : evidence.text);
        String jsRole = FindHintBuilder.jsSingleQuoteEscape(evidence.role == null ? "" : evidence.role);
        String jsType = FindHintBuilder.jsSingleQuoteEscape(evidence.type == null ? "" : evidence.type);
        return """
            (() => {
              const matches = [];
              const seen = new Set();
              const add = el => { if (el && !seen.has(el)) { seen.add(el); matches.push(el); } };
              const roots = [document];
              [...document.querySelectorAll('*')].forEach(el => { if (el.shadowRoot) roots.push(el.shadowRoot); });
              [...document.querySelectorAll('iframe')].forEach(frame => { try { if (frame.contentDocument) roots.push(frame.contentDocument); } catch (e) {} });
              roots.forEach(root => {
                try {
                  __BASE_LOCATE__
                  if (!matches.length && '__TEXT__') {
                    root.querySelectorAll('button,a,input,select,textarea,[role],[role="button"]').forEach(el => {
                      const textValue = (el.innerText || el.textContent || el.value || '').replace(/\s+/g, ' ').trim().toLowerCase();
                      if (textValue !== '__TEXT__'.trim().toLowerCase()) return;
                      if ('__ROLE__' && el.getAttribute('role') !== '__ROLE__') return;
                      if ('__TYPE__' && (el.getAttribute('type') || '').toLowerCase() !== '__TYPE__') return;
                      add(el);
                    });
                  }
                } catch (e) {}
              });
              matches.forEach((el, i) => {
                el.dataset.clientsideeyeOutline = el.style.outline || '';
                el.dataset.clientsideeyeOutlineOffset = el.style.outlineOffset || '';
                el.style.outline = '3px solid #ff4d4f';
                el.style.outlineOffset = '2px';
                console.log('[ClientSideEye] highlighted match', i, el);
              });
              setTimeout(() => matches.forEach(el => {
                el.style.outline = el.dataset.clientsideeyeOutline || '';
                el.style.outlineOffset = el.dataset.clientsideeyeOutlineOffset || '';
              }), 4000);
              if (matches[0]) matches[0].scrollIntoView({block:'center'});
              return matches;
            })()
            """
            .replace("__BASE_LOCATE__", baseLocate)
            .replace("__TEXT__", jsText)
            .replace("__ROLE__", jsRole)
            .replace("__TYPE__", jsType)
            .trim();
    }

    static String revealSnippet(String selector, FindHintEvidence evidence) {
        String jsSelector = FindHintBuilder.jsSingleQuoteEscape(selector == null ? "" : selector);
        String jsTestId = FindHintBuilder.jsSingleQuoteEscape(evidence.dataTestId == null ? "" : evidence.dataTestId);
        String jsText = FindHintBuilder.jsSingleQuoteEscape(evidence.text == null ? "" : evidence.text);
        String jsRole = FindHintBuilder.jsSingleQuoteEscape(evidence.role == null ? "" : evidence.role);
        String jsType = FindHintBuilder.jsSingleQuoteEscape(evidence.type == null ? "" : evidence.type);
        String testIdSelector = FindHintBuilder.jsDoubleQuoteEscape(evidence.dataTestId == null ? "" : evidence.dataTestId);
        return """
            (() => {
              const matches = [];
              const seen = new Set();
              const add = el => { if (el && !seen.has(el)) { seen.add(el); matches.push(el); } };
              const roots = [document];
              [...document.querySelectorAll('*')].forEach(el => { if (el.shadowRoot) roots.push(el.shadowRoot); });
              [...document.querySelectorAll('iframe')].forEach(frame => { try { if (frame.contentDocument) roots.push(frame.contentDocument); } catch (e) {} });
              roots.forEach(root => {
                try {
                  if ('__SELECTOR__') root.querySelectorAll('__SELECTOR__').forEach(add);
                  if (!matches.length && '__TEST_ID__') root.querySelectorAll('[data-testid="__TEST_ID_SELECTOR__"]').forEach(add);
                  if (!matches.length && '__TEXT__') {
                    root.querySelectorAll('button,a,input,select,textarea,[role],[role="button"]').forEach(el => {
                      const textValue = (el.innerText || el.textContent || el.value || '').replace(/\s+/g, ' ').trim().toLowerCase();
                      if (textValue !== '__TEXT__'.trim().toLowerCase()) return;
                      if ('__ROLE__' && el.getAttribute('role') !== '__ROLE__') return;
                      if ('__TYPE__' && (el.getAttribute('type') || '').toLowerCase() !== '__TYPE__') return;
                      add(el);
                    });
                  }
                } catch (e) {}
              });
              const revealOne = (el) => {
                let node = el;
                while (node && node.nodeType === 1) {
                  node.hidden = false;
                  node.removeAttribute && node.removeAttribute('hidden');
                  node.removeAttribute && node.removeAttribute('aria-hidden');
                  if (node.style) {
                    if (node.style.display === 'none') node.style.display = '';
                    node.style.visibility = 'visible';
                    node.style.opacity = '1';
                    node.style.pointerEvents = 'auto';
                    node.style.filter = '';
                    node.style.maxHeight = '';
                    node.style.overflow = 'visible';
                  }
                  if ('disabled' in node) node.disabled = false;
                  node.removeAttribute && node.removeAttribute('disabled');
                  node.removeAttribute && node.removeAttribute('aria-disabled');
                  if (node.classList) node.classList.remove('pf-m-disabled','is-disabled','btn-disabled','disabled','hidden','d-none');
                  node = node.parentElement;
                }
                el.scrollIntoView({block:'center'});
                el.focus && el.focus({preventScroll:true});
                el.style.outline = '3px solid #fa8c16';
              };
              matches.forEach(revealOne);
              matches.forEach((el, i) => console.log('[ClientSideEye] revealed match', i, el));
              if (!matches.length) return console.log('[ClientSideEye] reveal target not found. Try the deep-locate hint first.');
              if (matches[0] && typeof inspect === 'function') inspect(matches[0]);
              return matches;
            })()
            """
            .replace("__SELECTOR__", jsSelector)
            .replace("__TEST_ID__", jsTestId)
            .replace("__TEST_ID_SELECTOR__", testIdSelector)
            .replace("__TEXT__", jsText)
            .replace("__ROLE__", jsRole)
            .replace("__TYPE__", jsType)
            .trim();
    }
}
