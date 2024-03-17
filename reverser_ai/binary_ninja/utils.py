import re


def is_derived_func_name(function_name):
    """
    Checks if the function name is derived by Binary Ninja
    due to API functions or symbols being present, or if it follows the 'sub_address' naming scheme (starts with 'sub_' followed
    by a lowercase hexadecimal sequence).

    Parameters:
    - function_name: The function name to be validated.

    Returns:
    - True if the name is derived (e.g., by symbols), False otherwise.
    """
    # Pattern for matching the 'sub_address' naming scheme
    sub_address_pattern = r'^sub_[0-9a-f]+$'

    # Check if the function name matches the 'sub_address' pattern
    if re.fullmatch(sub_address_pattern, function_name):
        return False

    return True
