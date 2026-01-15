import React from 'react';
import './Technology.css';

const Technology = () => {
    return (
        <section className="technology section" id="technology">
            <div className="technology__container container">
                <div className="technology__grid">
                    {/* Image Side */}
                    <div className="technology__visual">
                        <div className="technology__image-wrapper">
                            <img
                                src="/ai_brain_network_1767644912481.png"
                                alt="AI Neural Network"
                                className="technology__image"
                            />
                            <div className="technology__image-glow"></div>
                        </div>
                    </div>

                    {/* Content Side */}
                    <div className="technology__content">
                        <span className="badge">Technology</span>
                        <h2 className="technology__title">
                            Powered by
                            <span className="text-gradient"> Advanced AI</span>
                        </h2>
                        <p className="technology__description">
                            Sentinel-X combines multiple AI technologies to create a defense system
                            that thinks, learns, and adapts faster than any human-operated solution.
                        </p>

                        {/* Features List */}
                        <ul className="technology__features">
                            <li className="technology__feature">
                                <div className="technology__feature-icon">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <polyline points="20,6 9,17 4,12" />
                                    </svg>
                                </div>
                                <div className="technology__feature-content">
                                    <h4>Graph Neural Networks</h4>
                                    <p>Detect coordinated botnet attacks by analyzing traffic patterns and relationships between requests.</p>
                                </div>
                            </li>
                            <li className="technology__feature">
                                <div className="technology__feature-icon">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <polyline points="20,6 9,17 4,12" />
                                    </svg>
                                </div>
                                <div className="technology__feature-content">
                                    <h4>LSTM Sequence Analysis</h4>
                                    <p>Model user sessions to identify anomalous behavior patterns and predict malicious intent.</p>
                                </div>
                            </li>
                            <li className="technology__feature">
                                <div className="technology__feature-icon">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <polyline points="20,6 9,17 4,12" />
                                    </svg>
                                </div>
                                <div className="technology__feature-content">
                                    <h4>Deep Q-Networks</h4>
                                    <p>Autonomous decision-making that learns optimal defense strategies from real-world interactions.</p>
                                </div>
                            </li>
                            <li className="technology__feature">
                                <div className="technology__feature-icon">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <polyline points="20,6 9,17 4,12" />
                                    </svg>
                                </div>
                                <div className="technology__feature-content">
                                    <h4>Automated Signature Generation</h4>
                                    <p>AI automatically creates and validates new attack signatures without human intervention.</p>
                                </div>
                            </li>
                        </ul>

                        <a href="#learn-more" className="btn btn-secondary technology__cta">
                            Explore Our Technology
                            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                                <path d="M6 12L10 8L6 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                            </svg>
                        </a>
                    </div>
                </div>
            </div>

            {/* Code Snippet Decoration */}
            <div className="technology__code-decoration">
                <pre>
                    <code>
                        {`// AI Decision Engine
const decision = await ai.analyze({
  request: incomingRequest,
  context: sessionHistory,
  threatLevel: currentThreatLevel
});

if (decision.action === 'BLOCK') {
  return sentinel.block(request);
}`}
                    </code>
                </pre>
            </div>
        </section>
    );
};

export default Technology;
