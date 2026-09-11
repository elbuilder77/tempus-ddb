const menu = document.querySelector('.menu-toggle');
const nav = document.querySelector('#main-nav');
if (menu && nav) {
  document.documentElement.classList.add('nav-enhanced');
  menu.hidden = false;
  const close = () => {
    menu.setAttribute('aria-expanded', 'false');
    nav.classList.remove('is-open');
  };
  menu.addEventListener('click', () => {
    const open = menu.getAttribute('aria-expanded') !== 'true';
    menu.setAttribute('aria-expanded', String(open));
    nav.classList.toggle('is-open', open);
  });
  nav.addEventListener('click', (event) => {
    if (event.target.closest('a')) close();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && menu.getAttribute('aria-expanded') === 'true') {
      close();
      menu.focus();
    }
  });
  document.addEventListener('click', (event) => {
    if (!event.target.closest('.header-inner')) close();
  });
  matchMedia('(min-width: 761px)').addEventListener('change', close);
}

const feedback = document.querySelector('#copy-status');
for (const button of document.querySelectorAll('[data-copy]')) {
  button.hidden = false;
  let resetTimer;
  button.addEventListener('click', async () => {
    const source = button.closest('.code-block, .install-line')?.querySelector('code');
    if (!source) return;
    clearTimeout(resetTimer);
    button.disabled = true;
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(source.textContent);
      button.textContent = 'Copied';
      feedback.textContent = 'Code copied to clipboard.';
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(source);
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = 'Selected';
      feedback.textContent = 'Clipboard unavailable. Code selected; use your device’s copy command.';
    } finally {
      button.disabled = false;
      resetTimer = setTimeout(() => { button.textContent = 'Copy'; }, 2500);
    }
  });
}

for (const pre of document.querySelectorAll('.code-block pre')) {
  pre.tabIndex = 0;
  pre.setAttribute('aria-label', 'Code example; scroll horizontally if needed');
}

const toc = document.querySelector('.doc-aside nav');
if (toc && 'IntersectionObserver' in window) {
  const observer = new IntersectionObserver((entries) => {
    const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
    if (!visible.length) return;
    for (const link of toc.querySelectorAll('a')) {
      if (link.hash === `#${visible[0].target.id}`) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    }
  }, { rootMargin: '-105px 0px -55% 0px' });
  document.querySelectorAll('.doc-card[id]').forEach((section) => observer.observe(section));
}
