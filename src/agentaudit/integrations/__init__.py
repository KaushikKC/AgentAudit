"""Framework integrations (differentiator D1).

AgentAudit is framework-agnostic: instrument any agent stack and get one audit
format. The neutral core is OpenTelemetry (:mod:`agentaudit.integrations.otel`);
thin adapters cover the popular frameworks directly
(:mod:`agentaudit.integrations.langchain`, :mod:`agentaudit.integrations.crewai`).

Each submodule imports its framework lazily/optionally, so importing this
package never requires OpenTelemetry, LangChain, or CrewAI to be installed.
"""

__all__ = ["otel", "langchain", "crewai"]
