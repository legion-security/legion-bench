"""Evaluation package for SOC investigation benchmark."""

from evaluation.models import EvaluationResult


def evaluate_investigation(*args, **kwargs):
    from evaluation.evaluate import evaluate_investigation as _impl
    return _impl(*args, **kwargs)


def evaluation_to_dict(*args, **kwargs):
    from evaluation.evaluate import evaluation_to_dict as _impl
    return _impl(*args, **kwargs)


def format_evaluation_report(*args, **kwargs):
    from evaluation.evaluate import format_evaluation_report as _impl
    return _impl(*args, **kwargs)


__all__ = [
    "EvaluationResult",
    "evaluate_investigation",
    "evaluation_to_dict",
    "format_evaluation_report",
]
