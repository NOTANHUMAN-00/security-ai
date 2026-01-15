import React, { useState, useEffect } from 'react';
import './Navbar.css';

const Navbar = () => {
    const [scrolled, setScrolled] = useState(false);
    const [mobileOpen, setMobileOpen] = useState(false);

    useEffect(() => {
        const handleScroll = () => {
            setScrolled(window.scrollY > 50);
        };
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    return (
        <nav className={`navbar ${scrolled ? 'navbar--scrolled' : ''}`}>
            <div className="navbar__container">
                {/* Logo */}
                <a href="#home" className="navbar__logo">
                    <div className="navbar__logo-icon">
                        <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M16 2L28 8V16C28 22.6274 22.6274 28 16 28C9.37258 28 4 22.6274 4 16V8L16 2Z"
                                stroke="currentColor" strokeWidth="2" fill="none" />
                            <path d="M16 8L22 11V16C22 19.3137 19.3137 22 16 22C12.6863 22 10 19.3137 10 16V11L16 8Z"
                                fill="currentColor" />
                        </svg>
                    </div>
                    <span className="navbar__logo-text">
                        Sentinel<span className="navbar__logo-x">-X</span>
                    </span>
                </a>

                {/* Desktop Navigation */}
                <div className="navbar__links">
                    <a href="#features" className="navbar__link">Features</a>
                    <a href="#technology" className="navbar__link">Technology</a>
                    <a href="#protection" className="navbar__link">Protection</a>
                    <a href="#docs" className="navbar__link">Docs</a>
                </div>

                {/* CTA Buttons */}
                <div className="navbar__cta">
                    <div className="navbar__github-disabled" data-tooltip="Coming Soon">
                        <svg viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                        </svg>
                    </div>
                    <div className="navbar__coming-soon-wrapper">
                        <span className="navbar__coming-soon-btn">
                            Coming Soon
                        </span>
                        <div className="navbar__flowing-line"></div>
                    </div>
                </div>

                {/* Mobile Toggle */}
                <button
                    className={`navbar__toggle ${mobileOpen ? 'active' : ''}`}
                    onClick={() => setMobileOpen(!mobileOpen)}
                    aria-label="Toggle menu"
                >
                    <span></span>
                    <span></span>
                    <span></span>
                </button>
            </div>

            {/* Mobile Menu */}
            <div className={`navbar__mobile ${mobileOpen ? 'open' : ''}`}>
                <a href="#features" className="navbar__mobile-link">Features</a>
                <a href="#technology" className="navbar__mobile-link">Technology</a>
                <a href="#protection" className="navbar__mobile-link">Protection</a>
                <a href="#docs" className="navbar__mobile-link">Docs</a>
                <div className="navbar__mobile-cta">
                    <span className="btn btn-secondary btn-large">Coming Soon</span>
                </div>
            </div>
        </nav>
    );
};

export default Navbar;
