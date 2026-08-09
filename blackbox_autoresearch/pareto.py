"""Small multi-objective Pareto frontier helper."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Objective:
    name: str
    direction: str

    def __post_init__(self) -> None:
        if self.direction not in {"maximize", "minimize"}:
            raise ValueError("objective direction must be maximize or minimize")


def pareto_frontier(
    points: dict[str, dict[str, float]],
    objectives: tuple[Objective, ...],
) -> tuple[str, ...]:
    if not objectives:
        raise ValueError("at least one objective is required")

    def dominates(left: dict[str, float], right: dict[str, float]) -> bool:
        no_worse = True
        strictly_better = False
        for objective in objectives:
            if objective.name not in left or objective.name not in right:
                raise ValueError(f"missing objective metric: {objective.name}")
            lval = left[objective.name]
            rval = right[objective.name]
            if objective.direction == "maximize":
                no_worse &= lval >= rval
                strictly_better |= lval > rval
            else:
                no_worse &= lval <= rval
                strictly_better |= lval < rval
        return no_worse and strictly_better

    frontier = []
    for candidate_id, metrics in points.items():
        if not any(
            other_id != candidate_id and dominates(other_metrics, metrics)
            for other_id, other_metrics in points.items()
        ):
            frontier.append(candidate_id)
    return tuple(sorted(frontier))
