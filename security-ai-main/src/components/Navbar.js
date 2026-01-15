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
                    <div className="navbar__github-wrapper">
                        <a
                            href="https://github.com/NOTANHUMAN-00/security-ai"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="navbar__github-btn"
                        >
                            Contribute on GitHub
                        </a>
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
                    <a
                        href="https://github.com/NOTANHUMAN-00/security-ai"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="btn btn-secondary btn-large"
                    >
                        Contribute on GitHub
                    </a>
                </div>
            </div>
        </nav>
    );
};

export default Navbar;
