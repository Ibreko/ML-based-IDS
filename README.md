# ML-based-IDS
🛡️ Sentinel-AI Pro: AI-Powered Network Intrusion Detection System
Sentinel-AI Pro is an advanced, modular cybersecurity platform designed for real-time network traffic analysis and anomaly detection. By leveraging Machine Learning (Random Forest) and a professional SOC-inspired interface, it transforms raw network logs into actionable security intelligence.

🚀 Key Features
🧠 Intelligent Traffic Analysis
ML-Based Detection: Utilizes a pre-trained Random Forest model to classify network traffic into "Normal" or "Anomaly" with high confidence scores.

Feature Importance Visualization: Integrated Explainable AI (XAI) components that show exactly which network parameters (flags, packet size, duration) triggered an alert.

🔍 Pro-Security & SOC Capabilities
MITRE ATT&CK Mapping: Automatically correlates detected anomalies with known adversary tactics and techniques.

Threat Intelligence Integration: Built-in hooks for VirusTotal API to check suspicious IP reputations on the fly.

Port Risk Assessment: Scans traffic for connections to critical or dangerous ports (e.g., RDP, Telnet, SMB) and flags them based on risk levels.

PCAP Processing: Includes utilities to convert raw PCAP files into structured data for analysis.

📊 Advanced Visual Analytics
Interactive Dashboard: Real-time metrics tracking total packets, threat counts, and AI confidence levels.

Geographic Threat Map: Visualizes the origin of malicious traffic using simulated geolocation clustering.

Security Timelines: Reconstructs incident sequences to help analysts understand the "blast radius" of an attack.

📄 Automated Reporting
One-Click PDF Export: Generates professional-grade security audit reports containing incident statistics and timestamps for compliance and documentation.

🏗️ System Architecture
The project follows a Modular Architecture to ensure scalability and maintainability:

app.py: The central Streamlit-powered command center.

core/: Machine Learning logic, model training, and inference engines.

utils/: Specialized security modules:

mitre_mapper.py: Expert-system for threat classification.

virustotal.py: External API connectors.

port_analyzer.py: Network protocol security logic.

pcap_converter.py: Traffic ingestion engine.

🛠️ Tech Stack
Language: Python 3.9+

Framework: Streamlit (Frontend/UI)

Data Science: Pandas, NumPy, Scikit-learn

Visuals: Plotly Express, Native Streamlit Maps

Security: Scapy (PCAP processing), VirusTotal API

📈 Future Roadmap (Advanced AI)
Ensemble Scoring: Implementing a "voting" system between Random Forest, XGBoost, and SVM for 99.9% accuracy.

Zero-Day Detection: Integrating Isolation Forest for unsupervised anomaly detection (finding threats never seen before).

Active Learning: A feedback loop where security analysts can "correct" the AI to refine the model over time.
