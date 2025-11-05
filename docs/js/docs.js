// Active navigation link based on scroll position
const docsSections = document.querySelectorAll('.doc-section');
const docsNavLinks = document.querySelectorAll('.docs-nav a');

window.addEventListener('scroll', () => {
    let current = '';

    docsSections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        if (window.pageYOffset >= sectionTop - 150) {
            current = section.getAttribute('id');
        }
    });

    docsNavLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${current}`) {
            link.classList.add('active');
        }
    });
});

// Add copy buttons to all code blocks
document.querySelectorAll('.code-block').forEach(block => {
    const button = document.createElement('button');
    button.className = 'copy-btn';
    button.textContent = 'Copy';

    button.addEventListener('click', async () => {
        const code = block.querySelector('code').textContent;
        try {
            await navigator.clipboard.writeText(code);
            button.textContent = '✓ Copied!';
            button.classList.add('copied');

            setTimeout(() => {
                button.textContent = 'Copy';
                button.classList.remove('copied');
            }, 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
            button.textContent = '✗ Failed';
            setTimeout(() => {
                button.textContent = 'Copy';
            }, 2000);
        }
    });

    block.appendChild(button);
});

// Highlight inline code in tables and lists
document.querySelectorAll('td code, li code').forEach(code => {
    code.style.cursor = 'pointer';
    code.title = 'Click to copy';

    code.addEventListener('click', async (e) => {
        e.stopPropagation();
        try {
            await navigator.clipboard.writeText(code.textContent);
            const originalBg = code.style.background;
            code.style.background = 'rgba(0, 255, 136, 0.2)';
            setTimeout(() => {
                code.style.background = originalBg;
            }, 500);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    });
});

// Animate elements on scroll
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const fadeInObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Animate concept cards and steps
document.querySelectorAll('.concept-card, .step, .command-card, .issue-card').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(30px)';
    el.style.transition = 'all 0.6s ease-out';
    fadeInObserver.observe(el);
});

// Add smooth scroll behavior for sidebar links
document.querySelectorAll('.docs-nav a').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = link.getAttribute('href').substring(1);
        const targetSection = document.getElementById(targetId);

        if (targetSection) {
            const offset = 100;
            const targetPosition = targetSection.offsetTop - offset;

            window.scrollTo({
                top: targetPosition,
                behavior: 'smooth'
            });

            // Update URL without scrolling
            history.pushState(null, null, `#${targetId}`);
        }
    });
});

// Handle direct links (when page loads with #hash)
window.addEventListener('load', () => {
    if (window.location.hash) {
        const targetId = window.location.hash.substring(1);
        const targetSection = document.getElementById(targetId);

        if (targetSection) {
            setTimeout(() => {
                const offset = 100;
                const targetPosition = targetSection.offsetTop - offset;
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }, 100);
        }
    }
});

// Add "Back to top" button
const backToTopButton = document.createElement('button');
backToTopButton.innerHTML = '<i class="fas fa-arrow-up"></i>';
backToTopButton.className = 'back-to-top';
backToTopButton.style.cssText = `
    position: fixed;
    bottom: 2rem;
    right: 2rem;
    background: var(--primary);
    color: var(--dark);
    border: none;
    width: 50px;
    height: 50px;
    border-radius: 50%;
    cursor: pointer;
    opacity: 0;
    visibility: hidden;
    transition: all 0.3s;
    z-index: 1000;
    box-shadow: 0 4px 12px rgba(0, 212, 255, 0.4);
`;

document.body.appendChild(backToTopButton);

window.addEventListener('scroll', () => {
    if (window.pageYOffset > 300) {
        backToTopButton.style.opacity = '1';
        backToTopButton.style.visibility = 'visible';
    } else {
        backToTopButton.style.opacity = '0';
        backToTopButton.style.visibility = 'hidden';
    }
});

backToTopButton.addEventListener('click', () => {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});

backToTopButton.addEventListener('mouseenter', () => {
    backToTopButton.style.transform = 'scale(1.1)';
});

backToTopButton.addEventListener('mouseleave', () => {
    backToTopButton.style.transform = 'scale(1)';
});

// Table of contents for longer sections (if exists)
const toc = document.querySelector('.toc');
if (toc) {
    const tocLinks = toc.querySelectorAll('a');
    tocLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href').substring(1);
            const targetSection = document.getElementById(targetId);

            if (targetSection) {
                const offset = 100;
                const targetPosition = targetSection.offsetTop - offset;
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// Search functionality (if search box is added later)
const createSearch = () => {
    const searchBox = document.createElement('div');
    searchBox.className = 'docs-search';
    searchBox.innerHTML = `
        <input type="text" placeholder="Search documentation..." />
        <i class="fas fa-search"></i>
    `;

    const sidebar = document.querySelector('.docs-sidebar');
    if (sidebar) {
        sidebar.insertBefore(searchBox, sidebar.firstChild);

        const searchInput = searchBox.querySelector('input');
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            const navLinks = document.querySelectorAll('.docs-nav li');

            navLinks.forEach(li => {
                const text = li.textContent.toLowerCase();
                if (text.includes(query) || query === '') {
                    li.style.display = 'block';
                } else {
                    li.style.display = 'none';
                }
            });
        });
    }
};

// Print button functionality
const addPrintButton = () => {
    const printBtn = document.createElement('button');
    printBtn.innerHTML = '<i class="fas fa-print"></i> Print';
    printBtn.className = 'print-btn';
    printBtn.style.cssText = `
        position: fixed;
        bottom: 2rem;
        left: 2rem;
        background: var(--dark-light);
        color: var(--text);
        border: 1px solid var(--primary);
        padding: 0.75rem 1.5rem;
        border-radius: 8px;
        cursor: pointer;
        opacity: 0;
        visibility: hidden;
        transition: all 0.3s;
        z-index: 1000;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    `;

    document.body.appendChild(printBtn);

    window.addEventListener('scroll', () => {
        if (window.pageYOffset > 300) {
            printBtn.style.opacity = '1';
            printBtn.style.visibility = 'visible';
        } else {
            printBtn.style.opacity = '0';
            printBtn.style.visibility = 'hidden';
        }
    });

    printBtn.addEventListener('click', () => {
        window.print();
    });

    printBtn.addEventListener('mouseenter', () => {
        printBtn.style.background = var(--primary);
        printBtn.style.color = var(--dark);
    });

    printBtn.addEventListener('mouseleave', () => {
        printBtn.style.background = var(--dark-light);
        printBtn.style.color = var(--text);
    });
};

// Initialize additional features
// createSearch(); // Uncomment to enable search
// addPrintButton(); // Uncomment to enable print button
