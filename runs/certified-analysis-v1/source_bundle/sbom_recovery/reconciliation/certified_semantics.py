"""Small, conservative marker semantics; the shared semantic trusted base.

The packaging 25.x marker AST is used explicitly and tested against complete
enumeration. Missing values never consult the host's default_environment.
"""
from __future__ import annotations

from packaging.markers import Marker, Variable
from packaging.utils import canonicalize_name

from .contracts_v2 import MARKER_NAMES


def expression_truth(expression, values):
    if isinstance(expression, tuple):
        variables = {v.value for v in expression if isinstance(v, Variable)}
        if any(v not in values or values[v] is None for v in variables):
            return None
        atom = " ".join(v.serialize() for v in expression)
        # Supply every supported variable, including variables not in this atom,
        # so packaging cannot replace a missing variable with a host value.
        environment = {k: values.get(k) or "" for k in MARKER_NAMES | {"extra"}}
        try:
            return Marker(atom).evaluate(environment=environment)
        except (ValueError, KeyError):
            return None
    groups, current = [], []
    for part in expression:
        if part == "or":
            groups.append(current)
            current = []
        elif part != "and":
            current.append(expression_truth(part, values))
    groups.append(current)
    conjunctions = [False if False in g else None if None in g else True for g in groups]
    return True if True in conjunctions else None if None in conjunctions else False


def for_extra(requirement, context, extra):
    if requirement.marker is None:
        return True
    return expression_truth(requirement.marker._markers, {**context.marker_values, "extra": extra})


def marker_bounds(requirement, context, known_extras, possible_extras=None):
    # The scope includes base requirements plus each activated extra, as in the
    # frozen reference contract. A partial bound may abstain on correlations.
    if any(for_extra(requirement, context, e) is True for e in {"", *known_extras}):
        return True
    possible = {"", *possible_extras} if possible_extras is not None else {"", None}
    return False if all(for_extra(requirement, context, e) is False for e in possible) else None


def initial_extras(context, inventory):
    return {key: {canonicalize_name(e) for e in context.root_requests.get(key) or []} for key in inventory}


def activation_bounds(view, context):
    """Construct lower derivations and an upper inductive invariant.

    In the all-installed declaration scope every distribution contributes its
    base requirements. An unread installed parent may request a child's extra;
    it is therefore deliberately NOT declared irrelevant to extra closure.
    Other local proofs (closed declarations/platform-false guards) still work.
    """
    known = initial_extras(context, view.inventory)
    steps = []
    changed = True
    while changed:
        changed = False
        for key, item in sorted(view.distributions.items()):
            for index, _, req in item.requirements:
                child = view.unique_child(req)
                if (child is None
                        or not req.extras or marker_bounds(req, context, known[key]) is not True):
                    continue
                additions = {canonicalize_name(e) for e in req.extras} - known[child]
                if additions:
                    known[child].update(additions)
                    steps.append({"source_id": item.source_id, "requirement_index": index,
                                  "child_occurrence": child})
                    changed = True
    upper = initial_extras(context, view.inventory)
    if (not context.root_requests_complete or set(context.root_requests) - view.inventory
            or not view.complete_inventory()):
        return known, None, steps
    changed = True
    while changed:
        changed = False
        for key, item in sorted(view.distributions.items()):
            for _, _, req in item.requirements:
                if not req.extras or marker_bounds(req, context, set(), upper[key]) is False:
                    continue
                matches = view.matching_children(req)
                if req.url or not matches:
                    return known, None, steps
                for child in matches:
                    additions = {canonicalize_name(e) for e in req.extras} - upper[child]
                    if additions:
                        upper[child].update(additions)
                        changed = True
    return known, upper, steps
