                                                    # Capstone Project Proposal
                                                    ## AI-Powered SOC Alert Triage Agent
                                                    ### Author: Ian Diaz


#Course:	Cybersecurity Capstone Project
##Instructor:	Dr. Kushi Gupta
###Date:	09/02/2026
###Project Title:	AI-Powered SOC Alert Triage Agent




1. Project Overview
Security Operations Center (SOC) analysts are routinely overwhelmed by the sheer volume of security alerts generated daily by SIEM and detection tooling, the large majority of which are false positives. This alert fatigue is widely cited as one of the leading contributors to analyst burnout and delayed response to genuine threats. This project proposes the design and implementation of an autonomous AI agent that automates the initial triage and enrichment stage of the SOC alert lifecycle, reducing the manual workload on human analysts while preserving human decision-making authority over any final response actions.
The agent will be built using Hermes Agent, an open-source, self-hosted agentic AI framework, paired with a locally-run large language model. The system will ingest raw security alerts, extract indicators of compromise (IOCs), enrich them using free threat intelligence APIs, map observed behavior to relevant MITRE ATT&CK techniques, and produce a ranked, human-readable triage report with a written justification for each severity assessment.

2. Problem Statement
Manual alert triage is time-consuming, inconsistent between analysts, and does not scale with the growing volume of telemetry produced by modern security infrastructure. Analysts frequently lack the time to enrich every alert with external context (threat intelligence, IOC reputation, known attack technique mapping) before deciding whether to escalate it. The result is either slow response to real incidents or wasted analyst hours chasing benign activity. There is a clear opportunity for an AI agent to absorb this repetitive, well-defined enrichment and prioritization work, allowing analysts to focus their expertise on genuine investigation and response.

3. Objectives
•	Design and implement an agentic pipeline that ingests raw security alerts and autonomously determines which enrichment lookups are relevant for each one.
•	Integrate free threat intelligence sources (VirusTotal, AbuseIPDB, WHOIS) to enrich extracted indicators of compromise.
•	Implement automated mapping of alert behavior to MITRE ATT&CK techniques.
•	Generate a severity score and natural-language justification for each alert, producing a ranked triage report.
•	Evaluate the system's accuracy and time savings against a labeled public dataset.
•	Document risk and governance considerations relevant to deploying autonomous agents in a security context.

4. Proposed Approach and Methodology
4.1 System Architecture
The system consists of an ingestion layer that accepts alert data in JSON or CSV format, a Hermes Agent core responsible for orchestration and decision-making, and a set of enrichment tools invoked by the agent as needed. Enrichment results, ATT&CK technique mapping, and severity scoring are combined into a final structured report.
4.2 Technology Stack
•	Agent Framework: Hermes Agent (open-source, MIT-licensed)
•	LLM Inference: Ollama, running a local open-source model (Llama 3.1 8B or Qwen 3 14B)
•	Enrichment APIs: VirusTotal (public tier), AbuseIPDB (free tier), public WHOIS
•	Execution Environment: Docker-based sandboxing (Hermes's built-in isolation)
•	Dataset: CICIDS2017 (public, labeled) and/or a synthetic alert generator

4.3 Agent Workflow
•	Ingest alert data and normalize fields (timestamp, source/destination IP, alert type, raw log).
•	Extract IOCs (IP addresses, file hashes, domains, URLs) from the alert.
•	Selectively enrich extracted IOCs using external threat intelligence APIs, with the agent deciding which lookups are warranted per alert rather than enriching indiscriminately.
•	Map observed alert behavior to a MITRE ATT&CK technique where applicable.
•	Generate a severity score with an accompanying natural-language justification.
•	Output a ranked triage report for analyst review.

5. Evaluation Plan
The system will be evaluated against a labeled subset of the CICIDS2017 dataset to allow for quantitative measurement. Planned metrics include:
•	Precision and recall of severity classification against ground-truth labels.
•	Estimated time-to-triage compared to a manual review baseline.
•	Enrichment efficiency: the proportion of API lookups the agent chose to skip via its own reasoning, compared to a naive baseline that enriches every indicator.
•	Qualitative review of generated justifications for accuracy and analyst usefulness.

6. Risk and Governance Considerations
Because this project involves an autonomous, tool-using agent, the following safeguards will be built into the design and discussed in the final report:
•	The agent will operate in a read-only, advisory capacity: it will enrich and recommend, but will not be granted permissions to take containment or remediation actions (e.g., host isolation, account disabling, firewall changes).
•	All agent execution will run inside Docker-based sandboxing to prevent unintended interaction with the host system.
•	A human analyst remains the final decision-maker for any escalation or response action; the agent's output is a recommendation, not an automated action.
•	Alert and log content will be treated as untrusted input, with consideration given to prompt-injection risks inherent to feeding externally-sourced text into an LLM-driven agent.
•	API credentials will be managed via environment variables rather than hardcoded values.

7. Timeline
A twelve-week implementation schedule is proposed:
•	Weeks 1–2: Environment setup (Hermes, Ollama, API access) and validation of basic agent functionality.
•	Week 3: Dataset preparation and IOC extraction development.
•	Weeks 4–5: Threat intelligence enrichment integration.
•	Week 6: Agentic decision logic for selective enrichment.
•	Weeks 7–8: Severity scoring, justification generation, and MITRE ATT&CK mapping.
•	Week 9: Triage report output and demo interface.
•	Week 10: Full evaluation run against labeled dataset.
•	Week 11: Written report and documentation.
•	Week 12: Final polish and presentation rehearsal.

8. Expected Outcomes and Deliverables
•	A working, demonstrable AI agent capable of triaging and enriching security alerts.
•	A quantitative evaluation report comparing agent performance to a labeled dataset baseline.
•	Complete source code and Hermes skill implementation.
•	A written report covering architecture, methodology, evaluation, and risk/governance analysis.
•	A live demonstration of the system processing a batch of sample alerts.

9. Cost and Resource Requirements
This project is designed to run entirely on free and open-source tooling. Hermes Agent is MIT-licensed and free to use; Ollama provides free local model inference with no per-token API costs; VirusTotal and AbuseIPDB offer free-tier API access sufficient for development and evaluation at capstone scale. The only requirement is a personal computer with at least 16GB of RAM capable of running a local language model.
