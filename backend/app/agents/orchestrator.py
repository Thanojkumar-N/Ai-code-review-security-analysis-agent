import time
import logging
from datetime import datetime
from typing import TypedDict, List, Dict, Any, Optional

from backend.app.agents.state import AgentState
from backend.app.agents.code_analysis_agent import code_analysis_agent_node
from backend.app.agents.security_agent import security_agent_node
from backend.app.agents.remediation_agent import remediation_agent_node
from backend.app.agents.pr_summary_agent import pr_summary_agent_node
from backend.app.agents.conversation_agent import conversation_agent_node

# Try importing LangGraph, fallback to custom StateGraph if not present
try:
    from langgraph.graph import StateGraph, START, END
except ImportError:
    from backend.app.agents.fallback_graph import StateGraph, END
    START = "__start__"

logger = logging.getLogger(__name__)

# State schema for the parallel workflow
class ParallelOrchestratorState(TypedDict):
    """The central state schema passed between nodes in the parallel review workflow."""
    code: str
    language: str
    code_analysis: Optional[Dict[str, Any]]
    security_analysis: Optional[Dict[str, Any]]
    status_code_analysis: Optional[Dict[str, Any]]
    status_security_analysis: Optional[Dict[str, Any]]
    analysis_findings: Optional[List[Dict[str, Any]]]
    security_findings: Optional[List[Dict[str, Any]]]
    merged_findings: Optional[List[Dict[str, Any]]]
    summary: Optional[Dict[str, Any]]
    start_time: Optional[float]

def get_review_workflow():
    """Build and compile the sequential code analysis, security, and PR summary agent workflow."""
    workflow = StateGraph(AgentState)
    
    # 1. Register Nodes
    workflow.add_node("code_analysis", code_analysis_agent_node)
    workflow.add_node("security_analysis", security_agent_node)
    workflow.add_node("remediation", remediation_agent_node)
    workflow.add_node("pr_summary", pr_summary_agent_node)
    
    # 2. Define Transitions (Edges)
    workflow.set_entry_point("code_analysis")
    workflow.add_edge("code_analysis", "security_analysis")
    workflow.add_edge("security_analysis", "remediation")
    workflow.add_edge("remediation", "pr_summary")
    workflow.add_edge("pr_summary", END)
    
    return workflow.compile()

def get_conversation_workflow():
    """Build and compile the conversation agent workflow for interactive Q&A."""
    workflow = StateGraph(AgentState)
    
    # Register Node
    workflow.add_node("conversation", conversation_agent_node)
    
    # Transitions
    workflow.set_entry_point("conversation")
    workflow.add_edge("conversation", END)
    
    return workflow.compile()

# Nodes for Parallel Orchestrator

def detect_language(code: str) -> str:
    """Helper to automatically detect the programming language of a source code block."""
    if "public class " in code or "import java." in code or "System.out.print" in code or "class " in code and ("{" in code or "public" in code or "private" in code):
        return "java"
    return "python"

def run_code_analysis(state: ParallelOrchestratorState) -> Dict[str, Any]:
    """Node wrapper for running the Code Analysis Agent with retry logic, logging, and execution timing."""
    start_time = time.time()
    retries = 3
    delay = 1.0
    agent_status = {
        "status": "pending",
        "execution_time_ms": 0.0,
        "retries": 0,
        "error": None
    }
    
    code = state.get("code", "")
    language = state.get("language", "")
    if not language or language.lower() not in ["python", "java"]:
        language = detect_language(code)
        
    local_state = dict(state)
    local_state["language"] = language
    
    for attempt in range(retries):
        try:
            logger.info(f"Running Code Analysis Agent (attempt {attempt + 1})")
            result = code_analysis_agent_node(local_state)
            
            duration_ms = (time.time() - start_time) * 1000
            agent_status.update({
                "status": "success",
                "execution_time_ms": round(duration_ms, 2),
                "retries": attempt,
                "error": None
            })
            return {
                "code_analysis": result.get("code_analysis"),
                "status_code_analysis": agent_status
            }
        except Exception as e:
            logger.error(f"Error running Code Analysis Agent (attempt {attempt + 1}): {str(e)}", exc_info=True)
            agent_status["retries"] = attempt + 1
            agent_status["error"] = str(e)
            if attempt < retries - 1:
                time.sleep(delay * (2 ** attempt))
            else:
                agent_status["status"] = "failed"
                
    duration_ms = (time.time() - start_time) * 1000
    agent_status["execution_time_ms"] = round(duration_ms, 2)
    return {
        "code_analysis": {"quality_findings": []},
        "status_code_analysis": agent_status
    }

def run_security_analysis(state: ParallelOrchestratorState) -> Dict[str, Any]:
    """Node wrapper for running the Security Vulnerability Agent with retry logic, logging, and execution timing."""
    start_time = time.time()
    retries = 3
    delay = 1.0
    agent_status = {
        "status": "pending",
        "execution_time_ms": 0.0,
        "retries": 0,
        "error": None
    }
    
    code = state.get("code", "")
    language = state.get("language", "")
    if not language or language.lower() not in ["python", "java"]:
        language = detect_language(code)
        
    local_state = dict(state)
    local_state["language"] = language
    
    for attempt in range(retries):
        try:
            logger.info(f"Running Security Vulnerability Agent (attempt {attempt + 1})")
            result = security_agent_node(local_state)
            
            duration_ms = (time.time() - start_time) * 1000
            agent_status.update({
                "status": "success",
                "execution_time_ms": round(duration_ms, 2),
                "retries": attempt,
                "error": None
            })
            return {
                "security_analysis": result.get("security_analysis"),
                "status_security_analysis": agent_status
            }
        except Exception as e:
            logger.error(f"Error running Security Vulnerability Agent (attempt {attempt + 1}): {str(e)}", exc_info=True)
            agent_status["retries"] = attempt + 1
            agent_status["error"] = str(e)
            if attempt < retries - 1:
                time.sleep(delay * (2 ** attempt))
            else:
                agent_status["status"] = "failed"
                
    duration_ms = (time.time() - start_time) * 1000
    agent_status["execution_time_ms"] = round(duration_ms, 2)
    return {
        "security_analysis": {"vulnerabilities": []},
        "status_security_analysis": agent_status
    }

def run_merge_findings(state: ParallelOrchestratorState) -> Dict[str, Any]:
    """Node for merging findings from Code Analysis and Security agents, sorting by severity, and recording metrics."""
    start_time = state.get("start_time") or time.time()
    
    analysis_data = state.get("code_analysis") or {}
    security_data = state.get("security_analysis") or {}
    
    analysis_findings = analysis_data.get("quality_findings") or []
    security_findings = security_data.get("vulnerabilities") or []
    
    # Merge and standardize source mapping
    merged_raw = []
    for f in analysis_findings:
        item = dict(f)
        item["source_agent"] = "code_analysis"
        item["line_number"] = item.get("line_number") or item.get("line") or 1
        item["line"] = item["line_number"]
        # Map snake to camel response items
        item["code_snippet"] = item.get("code_snippet") or item.get("snippet") or ""
        item["snippet"] = item["code_snippet"]
        merged_raw.append(item)
        
    for f in security_findings:
        item = dict(f)
        item["source_agent"] = "security_analysis"
        item["line_number"] = item.get("line_number") or item.get("line") or 1
        item["line"] = item["line_number"]
        # Map snake/camel security values
        item["Issue Name"] = item.get("Issue Name") or item.get("issue_name") or item.get("title") or "Security Issue"
        item["issue_name"] = item["Issue Name"]
        item["OWASP Category"] = item.get("OWASP Category") or item.get("owasp_category") or item.get("classification") or "OWASP Top 10"
        item["owasp_category"] = item["OWASP Category"]
        item["Severity"] = item.get("Severity") or item.get("severity") or "Medium"
        item["severity"] = item["Severity"]
        item["Description"] = item.get("Description") or item.get("description") or ""
        item["description"] = item["Description"]
        item["Affected File"] = item.get("Affected File") or item.get("affected_file") or "main.py"
        item["affected_file"] = item["Affected File"]
        item["Line Number"] = item["line_number"]
        item["Code Snippet"] = item.get("Code Snippet") or item.get("code_snippet") or item.get("snippet") or ""
        item["code_snippet"] = item["Code Snippet"]
        item["snippet"] = item["Code Snippet"]
        item["Risk Explanation"] = item.get("Risk Explanation") or item.get("risk_explanation") or ""
        item["risk_explanation"] = item["Risk Explanation"]
        item["Recommended Fix"] = item.get("Recommended Fix") or item.get("recommended_fix") or item.get("recommendation") or ""
        item["recommended_fix"] = item["Recommended Fix"]
        item["Corrected Code Example"] = item.get("Corrected Code Example") or item.get("corrected_code_example") or item.get("corrected_code") or ""
        item["corrected_code_example"] = item["Corrected Code Example"]
        merged_raw.append(item)
        
    # De-duplicate: Keep first finding if multiple share same line, and code smell category / vulnerability title
    seen = set()
    de_duplicated = []
    for f in merged_raw:
        key = (f.get("line_number"), f.get("id") or f.get("title") or f.get("issue_name") or "")
        if key not in seen:
            seen.add(key)
            de_duplicated.append(f)
            
    # Sort by severity priority: Critical > High > Medium > Low > Info
    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "unknown": 5
    }
    
    def get_severity_rank(f):
        sev = f.get("severity") or f.get("Severity") or "unknown"
        return SEVERITY_ORDER.get(str(sev).lower(), 5)
        
    de_duplicated.sort(key=lambda x: (get_severity_rank(x), x.get("line_number", 0)))
    
    # Calculate counts by severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in de_duplicated:
        sev = str(f.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
            
    # Compute overall score
    deductions = counts["critical"] * 25 + counts["high"] * 15 + counts["medium"] * 5 + counts["low"] * 2
    overall_score = max(0, 100 - deductions)
    
    # Collect unique recommendations
    recommendations = []
    for f in de_duplicated:
        rec = f.get("recommendation") or f.get("recommended_fix") or ""
        if rec and rec not in recommendations:
            recommendations.append(rec)
            
    total_time_ms = (time.time() - start_time) * 1000
    
    summary = {
        "total_execution_time_ms": round(total_time_ms, 2),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(de_duplicated),
        "analysis_findings_count": sum(1 for f in de_duplicated if f["source_agent"] == "code_analysis"),
        "security_findings_count": sum(1 for f in de_duplicated if f["source_agent"] == "security_analysis"),
        "severity_summary": counts,
        "overall_score": overall_score,
        "agent_status": {
            "code_analysis": state.get("status_code_analysis") or {},
            "security_analysis": state.get("status_security_analysis") or {}
        }
    }
    
    de_dup_analysis = [f for f in de_duplicated if f["source_agent"] == "code_analysis"]
    de_dup_security = [f for f in de_duplicated if f["source_agent"] == "security_analysis"]
    
    return {
        "analysis_findings": de_dup_analysis,
        "code_analysis_findings": de_dup_analysis,
        "security_findings": de_dup_security,
        "merged_findings": de_duplicated,
        "overall_score": overall_score,
        "recommendations": recommendations[:5],
        "summary": summary
    }

def get_parallel_review_workflow():
    """Build and compile the parallel code review workflow using LangGraph."""
    workflow = StateGraph(ParallelOrchestratorState)
    
    # 1. Register Nodes
    workflow.add_node("code_analysis", run_code_analysis)
    workflow.add_node("security_analysis", run_security_analysis)
    workflow.add_node("merge_findings", run_merge_findings)
    
    # 2. Define Transitions (Edges)
    workflow.add_edge(START, "code_analysis")
    workflow.add_edge(START, "security_analysis")
    workflow.add_edge("code_analysis", "merge_findings")
    workflow.add_edge("security_analysis", "merge_findings")
    workflow.add_edge("merge_findings", END)
    
    return workflow.compile()

