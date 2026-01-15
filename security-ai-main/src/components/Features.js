import React from 'react';
import './Features.css';

const features = [
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 2L4 6V12C4 17.52 7.53 22.53 12 23.99C16.47 22.53 20 17.52 20 12V6L12 2Z" />
                <path d="M9 12L11 14L15 10" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
        ),
        title: 'AI-Powered Detection',
        description: 'Machine learning models trained on millions of attack patterns identify threats in real-time with 99.99% accuracy.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 2L4 7V11C4 16.55 7.16 21.74 12 23C16.84 21.74 20 16.55 20 11V7L12 2Z" />
                <path d="M9 12L11 14L15 10" strokeLinecap="round" strokeLinejoin="round" />
                <circle cx="12" cy="8" r="2" />
            </svg>
        ),
        title: 'JA3 TLS Fingerprinting',
        description: 'Identify bots and attackers by analyzing unique TLS handshake patterns, detecting even the most sophisticated scrapers.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <rect x="3" y="3" width="7" height="7" rx="1" />
                <rect x="14" y="3" width="7" height="7" rx="1" />
                <rect x="3" y="14" width="7" height="7" rx="1" />
                <rect x="14" y="14" width="7" height="7" rx="1" />
                <path d="M10 6.5H14M6.5 10V14M17.5 10V14M10 17.5H14" />
            </svg>
        ),
        title: 'GNN Botnet Detection',
        description: 'Graph Neural Networks analyze traffic relationships to detect coordinated botnet attacks and DDoS attacks.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 2L2 7L12 12L22 7L12 2Z" />
                <path d="M2 17L12 22L22 17" />
                <path d="M2 12L12 17L22 12" />
            </svg>
        ),
        title: 'Adaptive Response',
        description: 'Deep reinforcement learning enables autonomous decision-making that evolves with emerging threat patterns.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M22 12H18L15 21L9 3L6 12H2" />
            </svg>
        ),
        title: 'Real-Time Analytics',
        description: 'Comprehensive dashboard with live metrics, attack visualization, and detailed threat intelligence reports.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 22C17.5228 22 22 17.5228 22 12C22 6.47715 17.5228 2 12 2C6.47715 2 2 6.47715 2 12C2 17.5228 6.47715 22 12 22Z" />
                <path d="M12 6V12L16 14" />
            </svg>
        ),
        title: 'Zero-Day Protection',
        description: 'Behavior-based detection identifies unknown threats before signatures exist, protecting against zero-day attacks.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
            </svg>
        ),
        title: 'API Protection',
        description: 'Comprehensive REST and GraphQL security with schema validation, rate limiting, and JWT verification.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M17 21V19C17 17.9391 16.5786 16.9217 15.8284 16.1716C15.0783 15.4214 14.0609 15 13 15H5C3.93913 15 2.92172 15.4214 2.17157 16.1716C1.42143 16.9217 1 17.9391 1 19V21" />
                <circle cx="9" cy="7" r="4" />
                <path d="M23 21V19C22.9993 18.1137 22.7044 17.2528 22.1614 16.5523C21.6184 15.8519 20.8581 15.3516 20 15.13" />
                <path d="M16 3.13C16.8604 3.3503 17.623 3.8507 18.1676 4.55231C18.7122 5.25392 19.0078 6.11683 19.0078 7.005C19.0078 7.89317 18.7122 8.75608 18.1676 9.45769C17.623 10.1593 16.8604 10.6597 16 10.88" />
            </svg>
        ),
        title: 'Bot Management',
        description: '75+ AI bot signatures with content poisoning, rate limiting, and intelligent challenge systems.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
                <path d="M3.27 6.96L12 12.01L20.73 6.96" />
                <path d="M12 22.08V12" />
            </svg>
        ),
        title: 'Kubernetes Native',
        description: 'Custom operators, Helm charts, and seamless integration with service mesh and cloud-native infrastructure.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M12 22S8 18 8 13V4L12 2L16 4V13C16 18 12 22 12 22Z" />
                <path d="M12 9V12" />
                <circle cx="12" cy="15" r="1" />
            </svg>
        ),
        title: 'Compliance Ready',
        description: 'SOC 2, PCI DSS, and GDPR compliant with automated reporting and comprehensive audit trails.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" />
            </svg>
        ),
        title: 'eBPF Acceleration',
        description: 'Kernel-level packet filtering with XDP for extreme performance: 10M+ requests per second.'
    },
    {
        icon: (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <rect x="2" y="3" width="20" height="14" rx="2" />
                <path d="M8 21H16" />
                <path d="M12 17V21" />
                <path d="M6 8H8" />
                <path d="M6 11H10" />
            </svg>
        ),
        title: 'Real-Time Dashboard',
        description: 'WebSocket-powered live updates with attack visualization, IP management, and configuration controls.'
    },
];

const Features = () => {
    return (
        <section className="features section" id="features">
            <div className="features__container container">
                <div className="features__header">
                    <span className="badge">Features</span>
                    <h2 className="features__title">
                        Enterprise-Grade
                        <span className="text-gradient"> Security</span>
                    </h2>
                    <p className="features__subtitle">
                        Everything you need to protect your applications from modern threats.
                    </p>
                </div>

                <div className="features__grid">
                    {features.map((feature, index) => (
                        <div key={index} className="feature-card">
                            <div className="feature-card__icon">
                                {feature.icon}
                            </div>
                            <h3 className="feature-card__title">{feature.title}</h3>
                            <p className="feature-card__description">{feature.description}</p>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
};

export default Features;
