(function () {
    var STORAGE_KEY = 'preferred-theme';

    function systemTheme() {
        return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function appliedTheme(savedTheme) {
        if (!savedTheme || savedTheme === 'system') {
            return systemTheme();
        }
        return savedTheme;
    }

    function applyTheme(savedTheme) {
        var active = appliedTheme(savedTheme);
        document.documentElement.setAttribute('data-theme', active);
        syncThemeUi(savedTheme || 'system', active);
    }

    function saveTheme(nextTheme) {
        if (nextTheme === 'system') {
            localStorage.removeItem(STORAGE_KEY);
            applyTheme('system');
            return;
        }
        localStorage.setItem(STORAGE_KEY, nextTheme);
        applyTheme(nextTheme);
    }

    function syncThemeUi(savedTheme, activeTheme) {
        var effectivePref = savedTheme === 'light' || savedTheme === 'dark' ? savedTheme : 'system';

        var status = document.querySelector('[data-theme-status]');
        if (status) {
            status.textContent = effectivePref + ' (' + activeTheme + ')';
        }

        document.querySelectorAll('[data-theme-set]').forEach(function (btn) {
            if (btn.getAttribute('data-theme-set') === effectivePref) {
                btn.classList.add('is-active');
            } else {
                btn.classList.remove('is-active');
            }
        });

        var quickToggle = document.querySelector('[data-theme-quick-toggle]');
        if (quickToggle) {
            var isDark = activeTheme === 'dark';
            quickToggle.textContent = isDark ? '☀' : '☾';
            quickToggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
            quickToggle.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
        }
    }

    function bindThemeButtons() {
        document.querySelectorAll('[data-theme-set]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var chosen = btn.getAttribute('data-theme-set');
                saveTheme(chosen);
            });
        });

        var quickToggle = document.querySelector('[data-theme-quick-toggle]');
        if (quickToggle) {
            quickToggle.addEventListener('click', function () {
                var active = document.documentElement.getAttribute('data-theme') || appliedTheme(localStorage.getItem(STORAGE_KEY) || 'system');
                var nextTheme = active === 'dark' ? 'light' : 'dark';
                saveTheme(nextTheme);
            });
        }
    }

    function init() {
        var saved = localStorage.getItem(STORAGE_KEY) || 'system';
        applyTheme(saved);
        bindThemeButtons();

        if (window.matchMedia) {
            var media = window.matchMedia('(prefers-color-scheme: dark)');
            media.addEventListener('change', function () {
                var current = localStorage.getItem(STORAGE_KEY) || 'system';
                if (current === 'system') {
                    applyTheme('system');
                }
            });
        }
    }

    document.addEventListener('DOMContentLoaded', init);
})();
