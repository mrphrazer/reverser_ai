import re

import networkx as nx
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
    Implements a worklist algorithm to traverse function call trees in a bottom-up manner as post-order traversal.

    This function creates an iterator that traverses nested function call trees from their leaves up to their roots,
    facilitating bottom-up analysis approaches where leaf-level information is propagated upwards in the call graph.
    This is particularly useful for scenarios where higher-level functions benefit from context provided by their leaf-level counterparts.

    Args:
        bv (binaryninja.BinaryView): The binary view representing the binary analysis context.

    Yields:
        binaryninja.Function: Functions from the binary view, traversed in a bottom-up order based on their call dependencies.
    """
    # Initialize a directed graph to represent the function call graph
    call_graph = nx.DiGraph()

    # Add all functions found in the binary view as nodes to the graph.
    call_graph.add_nodes_from(bv.functions)

    # Iterate over each function in the binary view to build edges in the graph based on call relationships.
    for f in bv.functions:
        # For each function, iterate over its callees (functions that it calls).
        for callee in f.callees:
            # Add an edge from the current function to each of its callees,
            # representing the call dependency in the graph.
            call_graph.add_edge(f, callee)

    # Perform a Depth-First Search (DFS) post-order traversal of the call graph.
    return nx.dfs_postorder_nodes(call_graph)


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
