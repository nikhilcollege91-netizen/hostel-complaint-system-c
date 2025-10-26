document.addEventListener('DOMContentLoaded', () => {

    // --- Loading Screen Logic ---
    const loader = document.getElementById('loader');
    if (loader) {
        // Hide loader initially
        loader.style.opacity = '0';
        loader.style.visibility = 'hidden';

        // Show loader on form submit or link click
        const forms = document.querySelectorAll('form');
        const links = document.querySelectorAll('a:not([target="_blank"])');

        const showLoader = () => {
            loader.style.opacity = '1';
            loader.style.visibility = 'visible';
        };

        forms.forEach(form => form.addEventListener('submit', showLoader));
        links.forEach(link => link.addEventListener('click', (e) => {
            // Only show loader for internal links, not external
            if (link.href && (link.href.includes(window.location.hostname) || link.href.startsWith('/'))) {
                showLoader();
            }
        }));

        // Hide loader when page is fully loaded
        const hideLoader = () => {
            loader.style.opacity = '0';
            loader.style.visibility = 'hidden';
            document.body.classList.add('loaded');
        };

        window.addEventListener('load', hideLoader);

        // Fix for back-button bfcache issue
        window.addEventListener('pageshow', (event) => {
            if (event.persisted) {
                hideLoader();
            }
        });
    }

    // --- Typewriter Effect for Home Page ---
    const taglineEl = document.getElementById('tagline');
    if (taglineEl) {
        const text = 'Register • Track • Resolve';
        let i = 0;
        const typeWriter = () => {
            if (i < text.length) {
                taglineEl.innerHTML += text.charAt(i);
                i++;
                setTimeout(typeWriter, 100);
            }
        };
        typeWriter();
    }

    // --- Auto-hide Flash Messages ---
    const flashMessages = document.querySelectorAll('.flash');
    if (flashMessages.length > 0) {
        flashMessages.forEach(msg => {
            setTimeout(() => {
                msg.style.transition = 'opacity 0.5s ease';
                msg.style.opacity = '0';
                setTimeout(() => msg.remove(), 500);
            }, 4000); // Hide after 4 seconds
        });
    }

});
