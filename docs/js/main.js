// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Active navigation link on scroll
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-menu a[href^="#"]');

window.addEventListener('scroll', () => {
    let current = '';
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        if (window.pageYOffset >= sectionTop - 200) {
            current = section.getAttribute('id');
        }
    });

    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${current}`) {
            link.classList.add('active');
        }
    });
});

// Animate elements on scroll
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

document.querySelectorAll('.feature-card, .example-card, .tool-category').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(30px)';
    el.style.transition = 'all 0.6s ease-out';
    observer.observe(el);
});

// Terminal typing effect (optional enhancement)
const terminalLines = document.querySelectorAll('.terminal-line .command');
terminalLines.forEach((line, index) => {
    const text = line.textContent;
    line.textContent = '';
    line.style.opacity = '0';

    setTimeout(() => {
        line.style.opacity = '1';
        let i = 0;
        const typing = setInterval(() => {
            if (i < text.length) {
                line.textContent += text.charAt(i);
                i++;
            } else {
                clearInterval(typing);
            }
        }, 50);
    }, index * 1000);
});

// Copy code on click
document.querySelectorAll('.example-card code').forEach(codeBlock => {
    codeBlock.style.cursor = 'pointer';
    codeBlock.title = 'Click to copy';

    codeBlock.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(codeBlock.textContent);
            const originalText = codeBlock.textContent;
            codeBlock.textContent = '✓ Copied!';
            codeBlock.style.color = 'var(--success)';

            setTimeout(() => {
                codeBlock.textContent = originalText;
                codeBlock.style.color = 'var(--text)';
            }, 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    });
});

// Stats counter animation
const statsNumbers = document.querySelectorAll('.stat-number');
const animateStats = () => {
    statsNumbers.forEach(stat => {
        const target = parseInt(stat.textContent);
        let current = 0;
        const increment = target / 50;
        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                stat.textContent = target + '+';
                clearInterval(timer);
            } else {
                stat.textContent = Math.ceil(current) + '+';
            }
        }, 30);
    });
};

// Trigger stats animation when hero is visible
const heroObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            animateStats();
            heroObserver.unobserve(entry.target);
        }
    });
}, { threshold: 0.5 });

const hero = document.querySelector('.hero');
if (hero) {
    heroObserver.observe(hero);
}


// Enhanced JavaScript Features

// Theme Toggle
const themeToggle = document.getElementById('theme-toggle');
if (themeToggle) {
    themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('light-theme');
        const icon = themeToggle.querySelector('i');
        icon.classList.toggle('fa-moon');
        icon.classList.toggle('fa-sun');
        localStorage.setItem('theme', document.body.classList.contains('light-theme') ? 'light' : 'dark');
    });
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light') {
        document.body.classList.add('light-theme');
        themeToggle.querySelector('i').classList.replace('fa-moon', 'fa-sun');
    }
}

// Mobile Menu Toggle
const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
const navMenu = document.getElementById('nav-menu');
if (mobileMenuToggle && navMenu) {
    mobileMenuToggle.addEventListener('click', () => {
        navMenu.classList.toggle('active');
        const icon = mobileMenuToggle.querySelector('i');
        icon.classList.toggle('fa-bars');
        icon.classList.toggle('fa-times');
    });
}

// FAQ Toggle
document.querySelectorAll('.faq-question').forEach(question => {
    question.addEventListener('click', () => {
        const faqItem = question.parentElement;
        const wasActive = faqItem.classList.contains('active');
        document.querySelectorAll('.faq-item').forEach(item => item.classList.remove('active'));
        if (!wasActive) faqItem.classList.add('active');
    });
});

// Parallax Effect
window.addEventListener('scroll', () => {
    const scrolled = window.pageYOffset;
    const hero = document.querySelector('.hero-content');
    if (hero && scrolled < 800) {
        hero.style.transform = 'translateY(' + (scrolled * 0.5) + 'px)';
        hero.style.opacity = 1 - (scrolled / 800);
    }
});

// Progress Bar
const progressBar = document.createElement('div');
progressBar.style.cssText = 'position:fixed;top:0;left:0;height:3px;background:linear-gradient(90deg,#00d4ff,#ff006e);z-index:10000;';
document.body.appendChild(progressBar);

window.addEventListener('scroll', () => {
    const winScroll = document.body.scrollTop || document.documentElement.scrollTop;
    const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    progressBar.style.width = ((winScroll / height) * 100) + '%';
});

// Console Easter Egg
console.log('%c⚠️ Penetration Test Suite v2.0.0', 'color:#00d4ff;font-size:16px;font-weight:bold;');
