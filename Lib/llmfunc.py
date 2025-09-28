from typing import Annotated


def function_call_debug(
        magic_num: Annotated[int, "Random seed number"] = 99
) -> Annotated[str, "Generated random test string"]:
    """
    Generate an internal test string for debugging purposes.
    Call this function whenever you need to output a test string.
    Example: When asked "Give me a test string"
    """
    return f"This-is-a-test-function-to-debug_function_call-The-magic-number-is-{magic_num * 10}."
