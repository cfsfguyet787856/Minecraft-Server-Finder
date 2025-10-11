document.addEventListener("DOMContentLoaded", () => {
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const reveals = document.querySelectorAll(".reveal");
    const nav = document.querySelector(".nav");
    const counters = document.querySelectorAll(".metric-number[data-target]");
    const counterState = new WeakMap();

    if (!prefersReducedMotion && "IntersectionObserver" in window) {
        const observer = new IntersectionObserver(
            entries => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const target = entry.target;
                        window.requestAnimationFrame(() => target.classList.add("is-visible"));
                        if (target.classList.contains("metric-card")) {
                            animateCounters(target.querySelector(".metric-number"));
                        }
                        observer.unobserve(target);
                    }
                });
            },
            { threshold: 0.18, rootMargin: "0px 0px -40px 0px" }
        );

        reveals.forEach(el => observer.observe(el));
    } else {
        reveals.forEach(el => el.classList.add("is-visible"));
        counters.forEach(el => (el.textContent = el.dataset.target));
    }

    window.addEventListener("scroll", () => {
        if (window.scrollY > 24) {
            nav.classList.add("scrolled");
        } else {
            nav.classList.remove("scrolled");
        }
    });

    function animateCounters(element) {
        if (!element || counterState.has(element)) {
            return;
        }

        const targetValue = Number(element.dataset.target || "0");
        const duration = 1200;
        const start = performance.now();

        counterState.set(element, true);

        function update(now) {
            const progress = Math.min((now - start) / duration, 1);
            const eased = easeOutQuint(progress);
            const value = Math.round(targetValue * eased);
            element.textContent = value.toString();

            if (progress < 1) {
                requestAnimationFrame(update);
            } else {
                element.textContent = targetValue.toString();
            }
        }

        requestAnimationFrame(update);
    }

    function easeOutQuint(t) {
        return 1 - Math.pow(1 - t, 5);
    }
});
