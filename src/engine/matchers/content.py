class ContentLimit(ValueError):
    pass


def match_content(conditions, payload, max_steps):
    states = {0: []}
    steps = 0
    folded = None
    for index, condition in enumerate(conditions):
        relative = condition.distance is not None or condition.within is not None
        prior = states.items() if relative else [next(iter(states.items()))]
        next_states = {}
        if condition.nocase and folded is None:
            folded = payload.lower()
        haystack = folded if condition.nocase else payload
        needle = condition.pattern.lower() if condition.nocase else condition.pattern
        for previous_end, history in prior:
            start = previous_end + (condition.distance or 0) if relative else (condition.offset or 0)
            end = len(payload)
            if relative and condition.within is not None:
                end = min(end, previous_end + condition.within)
            elif not relative and condition.depth is not None:
                end = min(end, start + condition.depth)
            position = start
            while position <= end - len(needle):
                steps += 1
                if steps > max_steps:
                    raise ContentLimit('content_search_limit')
                found = haystack.find(needle, position, end)
                if found < 0:
                    break
                finish = found + len(needle)
                next_states.setdefault(finish, history + [{'content_index': index, 'start': found, 'end': finish,
                                                          'pattern_hex': condition.pattern.hex()}])
                position = found + 1
        if not next_states:
            return None
        states = next_states
    return next(iter(states.values()))
