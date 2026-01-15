import React from 'react';
import './Protection.css';

const stats = [
    {
        value: '10M+',
        label: 'Threats Analyzed',
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 2L4 6V12C4 17.52 7.53 22.53 12 23.99C16.47 22.53 20 17.52 20 12V6L12 2Z" strokeLinejoin="round" />
                <path d="M9 12L11 14L15 10" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
        )
    },
    {
        value: '99.99%',
        label: 'Detection Accuracy',
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <circle cx="12" cy="12" r="6" />
                <circle cx="12" cy="12" r="2" />
            </svg>
        )
    },
    {
        value: '<2ms',
        label: 'Response Time',
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" strokeLinejoin="round" />
            </svg>
        )
    },
    {
        value: '24/7',
        label: 'Real-Time Protection',
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 6V12L16 14" />
            </svg>
        )
    },
];

const Protection = () => {
    return (
        <section className="protection section" id="protection">
            <div className="protection__container container">
                {/* Two Column Layout */}
                <div className="protection__grid">
                    {/* Left - Visual (Security Command Center) */}
                    <div className="protection__visual">
                        <div className="protection__image-wrapper">
                            <img
                                src="/security_command_1767648124336.png"
                                alt="AI Security Command Center"
                                className="protection__image"
                            />
                            <div className="protection__image-glow"></div>
                        </div>
                    </div>

                    {/* Right - Content */}
                    <div className="protection__content">
                        <span className="badge">AI Protection</span>
                        <h2 className="protection__title">
                            Autonomous Defense
                            <span className="text-gradient"> Network</span>
                        </h2>
                        <p className="protection__description">
                            Sentinel-X provides next-generation protection powered by advanced AI and machine learning.
                            Visualize threats in real-time through our advanced command center and automated response systems.
                        </p>

                        {/* Stats Grid */}
                        <div className="protection__stats">
                            {stats.map((stat, index) => (
                                <div key={index} className="protection__stat-card">
                                    <div className="protection__stat-icon">{stat.icon}</div>
                                    <div className="protection__stat-content">
                                        <span className="protection__stat-value">{stat.value}</span>
                                        <span className="protection__stat-label">{stat.label}</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* CTA with background image */}
                <div className="protection__cta">
                    <div className="protection__cta-bg">
                        <img src="/cta_background_1767646181217.png" alt="" />
                    </div>
                    <div className="protection__cta-content">
                        <h3 className="protection__cta-title">Join the Open-Source Security Movement</h3>
                        <p className="protection__cta-text">
                            Sentinel-X is free and open source. Deploy it now or contribute to the project on GitHub.
                        </p>
                        <div className="protection__cta-buttons">
                            <a
                                href="https://github.com/NOTANHUMAN-00/security-ai"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="btn btn-primary btn-large"
                            >
                                Contribute on GitHub
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default Protection;
