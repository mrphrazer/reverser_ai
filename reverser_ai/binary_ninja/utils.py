import re
from binaryninja.enums import SymbolType


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


def traverse_functions_bottom_up(bv):
    """
    Implements a worklist algorithm to traverse function call trees in a bottom-up manner.

    This function creates an iterator that traverses nested function call trees from their leaves up to their roots,
    facilitating bottom-up analysis approaches where leaf-level information is propagated upwards in the call graph.
    This is particularly useful for scenarios where higher-level functions benefit from context provided by their leaf-level counterparts.

    TODO: Current implementation triggers an endless loop because of inproper handling of re-adding
          function callers again. Must be refactored into a clean version of iterative post-order traversal.

    Args:
        bv (binaryninja.BinaryView): The binary view representing the binary analysis context.

    Yields:
        binaryninja.Function: Functions from the binary view, traversed in a bottom-up order based on their call dependencies.
    """
    # Initialize the 'done' set, ensuring processed functions are skipped during traversal
    done = set()

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
            else:
                # Ensure current function is reconsidered after processing its callees
                todo.append(current)

                # Add unprocessed callees to the worklist for processing
                for callee in current.callees:
                    if callee not in done:
                        todo.append(callee)


def collect_symbol_related_functions(bv):
    """
    Identifies functions interacting with symbols of library functions, imports/exports,
    and external data within a binary view.

    Targets symbols related to data variables, specifically focusing on import addresses,
    library functions, external symbols, imported data, and imported functions. It aggregates
    all functions that reference these symbols, offering a concise set for detailed analysis.

    Args:
        bv (binaryninja.BinaryView): The binary view of the analysis target.

    Returns:
        set: A set of functions associated with specified symbol types.
    """
    # Define the set of symbol types we are interested in.
    target_symbol_types = {
        SymbolType.ImportAddressSymbol,
        SymbolType.LibraryFunctionSymbol,
        SymbolType.ExternalSymbol,
        SymbolType.ImportedDataSymbol,
        SymbolType.ImportedFunctionSymbol
    }

    # Initialize an empty set to store functions associated with the target symbols.
    preselected_functions = set()

    # Iterate over all data variables in the binary to check for associated symbols.
    for address in bv.data_vars:
        # Retrieve the data variable at the current address.
        data_var = bv.get_data_var_at(address)

        # Skip data variables that either have no symbol or whose symbol type is not in our target list.
        if not data_var.symbol or data_var.symbol.type not in target_symbol_types:
            continue

        # For each data variable that meets the criteria, add the functions that reference it to our set.
        preselected_functions.update(
            code_ref.function for code_ref in data_var.code_refs)

    return preselected_functions


def collect_string_related_functions(bv):
    """
    Collects functions that interact with string references within a binary view.

    This function iterates over all strings found in the binary, checking for data variables
    at the strings' starting addresses. It then collects functions that reference these data
    variables.

    Args:
        bv (binaryninja.BinaryView): The binary view containing the target binary's data.

    Returns:
        Set[binaryninja.Function]: A set of functions that reference string-related data variables.
    """
    # Initialize an empty set to hold functions associated with strings.
    preselected_functions = set()

    # Iterate over all strings in the binary view.
    for s in bv.strings:
        # Attempt to retrieve the data variable at the string's start address.
        data_var = bv.get_data_var_at(s.start)

        # Skip iteration if no data variable is found at the string's location.
        if data_var is None:
            continue

        # Add functions that reference the located data variable to set.
        for code_ref in data_var.code_refs:
            preselected_functions.add(code_ref.function)

    return preselected_functions
