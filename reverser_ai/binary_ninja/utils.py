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


def traverse_functions_bottom_up(bv, preselected_functions=None):
    """
    Implements a worklist algorithm to traverse function call trees in a bottom-up manner.

    This function creates an iterator that traverses nested function call trees from their leaves up to their roots,
    facilitating bottom-up analysis approaches where leaf-level information is propagated upwards in the call graph.
    This is particularly useful for scenarios where higher-level functions benefit from context provided by their leaf-level counterparts.

    Optionally, a set of preselected 'interesting' functions can be specified, limiting the traversal to these functions
    and their call dependencies. This allows for focused analysis on a subset of the binary's functions deemed most relevant.

    Args:
        bv (binaryninja.BinaryView): The binary view representing the binary analysis context.
        preselected_functions (set, optional): A set of function names considered 'interesting' for targeted analysis. Defaults to None.

    Yields:
        binaryninja.Function: Functions from the binary view, traversed in a bottom-up order based on their call dependencies.
    """
    # Initialize preselected functions to an empty set if None provided
    preselected_functions = preselected_functions or {}

    # Initialize the 'done' set with functions not in 'preselected_functions', ensuring they're skipped during traversal
    done = set() if not preselected_functions else {
        f for f in bv.functions if f.name not in preselected_functions}

    # Worklist of functions pending processing, for bottom-up traversal
    todo = []

    # Populate the worklist with functions not already processed or preselected
    for f in bv.functions:
        if f not in done:
            todo.append(f)

        # Process functions in the worklist, respecting call dependencies
        while len(todo) != 0:
            # Retrieve the most recently added function
            current = todo.pop()

            # Skip already processed functions
            if current in done:
                continue

            # Check if all callees of the current function have been processed
            if all(callee in done for callee in current.callees):
                # Mark the current function as processed
                done.add(current)
                # Yield the current function for bottom-up analysis
                yield current

            # Ensure current function is reconsidered after processing its callees
            todo.append(current)

            # Add unprocessed callees to the worklist for processing
            for callee in current.callees:
                if callee not in done:
                    todo.append(callee)
