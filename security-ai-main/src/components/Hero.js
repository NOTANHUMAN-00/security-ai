import React, { useState } from 'react';
import './Hero.css';

const Hero = () => {
    const [showVideo, setShowVideo] = useState(false);

    return (
        <section className="hero" id="home">
            {/* Background Effects */}
            <div className="hero__bg">
                <div className="hero__gradient-orb hero__gradient-orb--1"></div>
                <div className="hero__gradient-orb hero__gradient-orb--2"></div>
                <div className="hero__grid"></div>
            </div>

            <div className="hero__container">
                <div className="hero__content">
                    {/* Heading */}
                    <h1 className="hero__title animate-fadeInUp">
                        The Future of
                        <span className="hero__title-highlight"> Web Security</span>
                        <br />
                        is Autonomous
                    </h1>

                    {/* Subtitle */}
                    <p className="hero__subtitle animate-fadeInUp animate-delay-1">
                        Open-source AI-powered WAF with advanced machine learning for real-time threat
                        detection. Build the future of web security with our autonomous defense platform.
                    </p>

                    {/* CTAs */}
                    <div className="hero__cta animate-fadeInUp animate-delay-2">
                        <a
                            href="https://github.com/NOTANHUMAN-00/security-ai"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn btn-primary btn-large hero__cta-primary"
                        >
                            Contribute on GitHub
                            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                                <path d="M7.5 15L12.5 10L7.5 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                            </svg>
                        </a>
                        <button
                            onClick={() => setShowVideo(true)}
                            className="btn btn-secondary btn-large hero__cta-secondary"
                        >
                            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                                <circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="1.5" />
                                <path d="M8.5 7.5L13 10L8.5 12.5V7.5Z" fill="currentColor" />
                            </svg>
                            Watch Demo
                        </button>
                    </div>

                    {/* Stats with animated line on left */}
                    <div className="hero__stats animate-fadeInUp animate-delay-3">
                        <div className="hero__stats-line"></div>
                        <div className="hero__stat">
                            <span className="hero__stat-value">10M+</span>
                            <span className="hero__stat-label">Threats Blocked</span>
                        </div>
                        <div className="hero__stat-divider"></div>
                        <div className="hero__stat">
                            <span className="hero__stat-value">&lt;2ms</span>
                            <span className="hero__stat-label">Latency</span>
                        </div>
                        <div className="hero__stat-divider"></div>
                        <div className="hero__stat">
                            <span className="hero__stat-value">99.99%</span>
                            <span className="hero__stat-label">Accuracy</span>
                        </div>
                    </div>
                </div>

                {/* Hero Image */}
                <div className="hero__visual animate-fadeInUp animate-delay-2">
                    <div className="hero__image-wrapper">
                        <img
                            src="/hero_shield_1767644894234.png"
                            alt="Sentinel-X AI Shield"
                            className="hero__image"
                        />
                        <div className="hero__image-glow"></div>
                    </div>
                </div>
            </div>

            {/* Video Popup Modal */}
            {showVideo && (
                <div className="video-modal" onClick={() => setShowVideo(false)}>
                    <div className="video-modal__content" onClick={(e) => e.stopPropagation()}>
                        <button className="video-modal__close" onClick={() => setShowVideo(false)}>
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M18 6L6 18M6 6l12 12" strokeLinecap="round" />
                            </svg>
                        </button>
                        <div className="video-modal__placeholder">
                            <div className="video-modal__icon">
                                <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
                                    <circle cx="40" cy="40" r="38" stroke="currentColor" strokeWidth="2" />
                                    <path d="M32 25L55 40L32 55V25Z" fill="currentColor" />
                                </svg>
                            </div>
                            <h3>Demo Video</h3>
                            <p>Video coming soon! We're preparing an in-depth walkthrough of Sentinel-X capabilities.</p>
                        </div>
                    </div>
                </div>
            )}
        </section>
    );
};

export default Hero;
