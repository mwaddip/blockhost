import DefaultTheme from 'vitepress/theme';
import type { Theme } from 'vitepress';
import { h } from 'vue';
import './custom.css';

export default {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'nav-bar-title-after': () =>
        h('span', { class: 'bh-site-title' }, [
          'Block',
          h('span', { class: 'bh-host' }, 'Host'),
        ]),
    });
  },
} satisfies Theme;
