import os
import json
import pytest
from backend.app.agents.orchestrator import get_parallel_review_workflow
from tests.validation_dataset import VALIDATION_DATASET

def test_automated_validation_metrics():
    workflow = get_parallel_review_workflow()
    
    TARGET_RULE_IDS = ["SEC-002", "QLY-001", "QLY-002", "QLY-004", "QLY-016", "QLY-BP-001"]
    
    tp = 0
    fp = 0
    fn = 0
    tn = 0
    
    details = []
    
    for case in VALIDATION_DATASET:
        code = case["code"]
        language = case["language"]
        expected = case["expected_findings"]
        expected_ids = [e["id"] for e in expected]
        
        result = workflow.invoke({
            "code": code,
            "language": language
        })
        
        merged_findings = result.get("merged_findings", [])
        raw_detected_ids = [f.get("id") for f in merged_findings]
        
        # Map equivalent findings from Bandit/Semgrep to target rule IDs
        detected_ids = []
        for det_id in raw_detected_ids:
            # Map SQL injection checks
            if any(term in det_id.lower() for term in ["b608", "sqli", "sql-query", "jdbc-sqli", "sql-string"]):
                detected_ids.append("SEC-002")
            # Map other rules
            else:
                detected_ids.append(det_id)
                
        case_tp = 0
        case_fp = 0
        case_fn = 0
        case_tn = 0
        
        for rule_id in TARGET_RULE_IDS:
            is_expected = rule_id in expected_ids
            is_detected = rule_id in detected_ids
            
            if is_expected and is_detected:
                case_tp += 1
            elif is_expected and not is_detected:
                case_fn += 1
            elif not is_expected and is_detected:
                case_fp += 1
            else:
                case_tn += 1
                
        tp += case_tp
        fp += case_fp
        fn += case_fn
        tn += case_tn
        
        details.append({
            "name": case["name"],
            "language": case["language"],
            "expected_ids": expected_ids,
            "detected_ids": [d for d in detected_ids if d in TARGET_RULE_IDS],
            "all_detected_ids": raw_detected_ids,
            "tp": case_tp,
            "fp": case_fp,
            "fn": case_fn,
            "tn": case_tn
        })
        
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 1.0
    detection_rate = recall
    
    report = {
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "accuracy": round(accuracy, 4),
            "detection_rate": round(detection_rate, 4),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn
        },
        "cases": details
    }
    
    os.makedirs("./reports", exist_ok=True)
    with open("./reports/validation_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        
    md_content = f"""# Validation Report - Multi-Agent Review Validation
    
## Summary Metrics
- **Precision**: {precision:.2%}
- **Recall / Detection Rate**: {recall:.2%}
- **Accuracy**: {accuracy:.2%}
- **True Positives**: {tp}
- **False Positives**: {fp}
- **False Negatives**: {fn}
- **True Negatives**: {tn}

## Test Cases Detailed Results
"""
    for d in details:
        md_content += f"""
### Case: {d['name']} ({d['language']})
- Expected Finding IDs: `{d['expected_ids']}`
- Detected Target IDs: `{d['detected_ids']}`
- All Detected IDs: `{d['all_detected_ids']}`
- Match counts: TP={d['tp']}, FP={d['fp']}, FN={d['fn']}, TN={d['tn']}
"""
        
    with open("./reports/validation_report.md", "w", encoding="utf-8") as f:
        f.write(md_content)
        
    assert accuracy >= 0.8
    assert recall >= 0.8
