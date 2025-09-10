#!/usr/bin/env python3
"""
Mitigation Workflows Module
Provides automated workflows for mitigation management.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum


class WorkflowStatus(Enum):
    """Workflow status levels."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class MitigationWorkflow:
    """
    Automated workflow management for mitigation recommendations.
    """
    
    def __init__(self):
        """Initialize mitigation workflow."""
        self.workflows = {}
    
    def create_workflow(self, scan_id: str, mitigation_plan: Dict[str, Any]) -> str:
        """
        Create a new mitigation workflow.
        
        Args:
            scan_id: Scan identifier
            mitigation_plan: Mitigation plan from MitigationEngine
            
        Returns:
            str: Workflow ID
        """
        workflow_id = f"workflow_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        workflow = {
            'workflow_id': workflow_id,
            'scan_id': scan_id,
            'status': WorkflowStatus.PENDING.value,
            'created_time': datetime.now().isoformat(),
            'updated_time': datetime.now().isoformat(),
            'mitigation_plan': mitigation_plan,
            'tasks': self._create_tasks(mitigation_plan),
            'progress': 0.0
        }
        
        self.workflows[workflow_id] = workflow
        return workflow_id
    
    def _create_tasks(self, mitigation_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create tasks from mitigation plan."""
        tasks = []
        
        for recommendation in mitigation_plan.get('mitigation_plan', []):
            for rec in recommendation.get('recommendations', []):
                task = {
                    'task_id': f"task_{len(tasks) + 1}",
                    'vulnerability_id': recommendation.get('vulnerability_id', ''),
                    'title': rec.get('action', ''),
                    'description': rec.get('description', ''),
                    'timeline': rec.get('timeline', ''),
                    'difficulty': rec.get('difficulty', 'medium'),
                    'status': WorkflowStatus.PENDING.value,
                    'assigned_to': None,
                    'due_date': self._calculate_due_date(rec.get('timeline', '')),
                    'created_time': datetime.now().isoformat(),
                    'completed_time': None
                }
                tasks.append(task)
        
        return tasks
    
    def _calculate_due_date(self, timeline: str) -> str:
        """Calculate due date based on timeline."""
        now = datetime.now()
        
        if timeline == 'immediate':
            return (now + timedelta(hours=24)).isoformat()
        elif timeline == 'short_term':
            return (now + timedelta(days=7)).isoformat()
        elif timeline == 'medium_term':
            return (now + timedelta(weeks=4)).isoformat()
        elif timeline == 'long_term':
            return (now + timedelta(days=90)).isoformat()
        else:
            return (now + timedelta(days=7)).isoformat()
    
    def update_task_status(self, workflow_id: str, task_id: str, 
                          status: WorkflowStatus, assigned_to: str = None) -> bool:
        """Update task status."""
        if workflow_id not in self.workflows:
            return False
        
        workflow = self.workflows[workflow_id]
        for task in workflow['tasks']:
            if task['task_id'] == task_id:
                task['status'] = status.value
                task['updated_time'] = datetime.now().isoformat()
                if assigned_to:
                    task['assigned_to'] = assigned_to
                if status == WorkflowStatus.COMPLETED:
                    task['completed_time'] = datetime.now().isoformat()
                
                # Update workflow progress
                self._update_workflow_progress(workflow_id)
                return True
        
        return False
    
    def _update_workflow_progress(self, workflow_id: str):
        """Update workflow progress percentage."""
        workflow = self.workflows[workflow_id]
        tasks = workflow['tasks']
        
        if not tasks:
            workflow['progress'] = 0.0
            return
        
        completed_tasks = len([t for t in tasks if t['status'] == WorkflowStatus.COMPLETED.value])
        workflow['progress'] = (completed_tasks / len(tasks)) * 100.0
        
        # Update workflow status
        if workflow['progress'] == 100.0:
            workflow['status'] = WorkflowStatus.COMPLETED.value
        elif completed_tasks > 0:
            workflow['status'] = WorkflowStatus.IN_PROGRESS.value
        
        workflow['updated_time'] = datetime.now().isoformat()
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow status."""
        return self.workflows.get(workflow_id)
    
    def get_overdue_tasks(self) -> List[Dict[str, Any]]:
        """Get overdue tasks across all workflows."""
        overdue_tasks = []
        now = datetime.now()
        
        for workflow in self.workflows.values():
            for task in workflow['tasks']:
                if task['status'] in [WorkflowStatus.PENDING.value, WorkflowStatus.IN_PROGRESS.value]:
                    due_date = datetime.fromisoformat(task['due_date'])
                    if now > due_date:
                        task['workflow_id'] = workflow['workflow_id']
                        overdue_tasks.append(task)
        
        return overdue_tasks
    
    def generate_workflow_report(self, workflow_id: str) -> str:
        """Generate workflow progress report."""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return "Workflow not found"
        
        report = f"""
# Mitigation Workflow Report

**Workflow ID**: {workflow['workflow_id']}
**Status**: {workflow['status']}
**Progress**: {workflow['progress']:.1f}%
**Created**: {workflow['created_time']}
**Updated**: {workflow['updated_time']}

## Task Summary
"""
        
        tasks = workflow['tasks']
        completed = len([t for t in tasks if t['status'] == WorkflowStatus.COMPLETED.value])
        in_progress = len([t for t in tasks if t['status'] == WorkflowStatus.IN_PROGRESS.value])
        pending = len([t for t in tasks if t['status'] == WorkflowStatus.PENDING.value])
        
        report += f"""
- **Total Tasks**: {len(tasks)}
- **Completed**: {completed}
- **In Progress**: {in_progress}
- **Pending**: {pending}

## Task Details
"""
        
        for task in tasks:
            status_icon = "✅" if task['status'] == WorkflowStatus.COMPLETED.value else "🔄" if task['status'] == WorkflowStatus.IN_PROGRESS.value else "⏳"
            report += f"""
### {status_icon} {task['title']}
- **Status**: {task['status']}
- **Timeline**: {task['timeline']}
- **Due Date**: {task['due_date']}
- **Assigned To**: {task['assigned_to'] or 'Unassigned'}
"""
        
        return report
