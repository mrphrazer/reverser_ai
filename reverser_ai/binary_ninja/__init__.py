from binaryninja.plugin import BackgroundTaskThread

from .function_name_gpt_wrapper import FunctionNameGPTWrapper
from .utils import (collect_string_related_functions,
                    collect_symbol_related_functions, is_derived_func_name,
                    traverse_functions_bottom_up)


class BGTask(BackgroundTaskThread):
    """
    Executes a provided function as a background task within the Binary Ninja environment.

    This class allows plugin commands to execute without blocking the main UI thread,
    enhancing responsiveness when performing potentially long-running operations.

    Attributes:
        bv (binaryninja.BinaryView): The binary view context for the operation.
        msg (str): A message describing the background task's purpose.
        f (function): The function to be executed in the background.
    """

    def __init__(self, bv, msg, f):
        super().__init__(msg, True)
        self.f = f
        self.bv = bv

    def run(self):
        """
        Executes the stored function with the provided binary view.
        """
        self.f(self.bv)


class BGTaskFunction(BackgroundTaskThread):
    """
    Specialized version of BGTask for executing functions that require an additional argument.

    Intended for use with Binary Ninja's PluginCommand.register_for_function, this class
    supports operations that act on specific items, like individual functions, within the binary.

    Attributes:
        bv (binaryninja.BinaryView): The binary view context for the operation.
        msg (str): A message describing the background task's purpose.
        f (function): The function to be executed in the background.
        arg (any): An additional argument to be passed to the function, typically a function object.
    """

    def __init__(self, bv, msg, f, arg):
        super().__init__(msg, True)
        self.f = f
        self.bv = bv
        self.arg = arg

    def run(self):
        """
        Executes the stored function with the provided binary view and additional argument.
        """
        self.f(self.bv, self.arg)


class BinjaFunctionNameGPTManager:
    """
    Manages a single instance of FunctionNameGPTWrapper to ensure it is initialized only once across multiple
    uses in the Binary Ninja plugin.

    This class implements the singleton design pattern to manage the unique and static initialization
    of FunctionNameGPTWrapper, which facilitates the application of GPT-based function naming suggestions
    within the Binary Ninja analysis environment.

    Attributes:
        _binja_function_name_gpt (FunctionNameGPTWrapper or None): A singleton instance of FunctionNameGPTWrapper.
    """

    def __init__(self):
        """
        Initializes the manager with a specified configuration path.
        """
        self._binja_function_name_gpt = None

    def get_instance(self):
        """
        Retrieves the singleton instance of FunctionNameGPTWrapper.

        If the instance has not been initialized, it initializes it.

        Returns:
            FunctionNameGPTWrapper: The initialized singleton instance of the wrapper.
        """
        if self._binja_function_name_gpt is None:
            self._binja_function_name_gpt = FunctionNameGPTWrapper()
        return self._binja_function_name_gpt


# Initialize the manager as a global variable to be reused across plugin functions
manager_function_name_gpt = BinjaFunctionNameGPTManager()


def plugin_wrapper_rename_function(_, f):
    """
    Queries FunctionNameGPTWrapper for a function name suggestion and applies it to a single function.

    This function is intended to be used as a callback or a hook within the Binary Ninja UI
    to rename a specific function.

    Args:
        _ : Ignored. Placeholder for the unused binary view.
        f (binaryninja.function.Function): The Binary Ninja function object to rename.
    """
    # Retrieve the singleton instance of the GPT manager
    gpt = manager_function_name_gpt.get_instance()

    # Apply the GPT-based name suggestion to the function
    gpt.apply_suggestion(f)


def plugin_wrapper_rename_all_functions(bv):
    """
    Iterates over all functions in a Binary Ninja binary view, querying a GPT-based model for name suggestions,
    and applies those suggestions to each function.

    This function ensures that functions are renamed in an order that respects
    their call dependencies. Specifically, it aims to rename "leaf" functions (those that do not call other functions)
    before renaming functions that call them. This approach facilitates the propagation of contextual information
    and learned insights across function names, potentially leading to more accurate and context-aware renaming.

    Due to the reliance on a GPT-based model for suggestions and the iterative nature of the algorithm, this operation
    can be slow, especially for binaries with a large number of functions.

    Args:
        bv (binaryninja.BinaryView): The binary view containing the functions to be renamed.
    """
    # Retrieve the singleton instance of the GPT manager for name suggestions
    gpt = manager_function_name_gpt.get_instance()

    # Iterates functions bottom-up to rename leaves first, improving context-awareness of GPT suggestions.
    # TODO: buttom-up traversal currently disabled due to a bug in the traversal algorithm
    for f in bv.functions(bv):
        # Apply the GPT-based name suggestion to the function if its actual name is not derived
        if not is_derived_func_name(f.name):
            gpt.apply_suggestion(f)


def plugin_wrapper_context_enriched_function_naming(bv):
    """
    Enhances function naming by leveraging context from strings and symbols.

    This plugin wrapper function utilizes a two-pronged approach to gather a rich context for function naming:
    1. Identifying functions that interact with strings and symbols, providing insights into potential functionalities.
    2. Employing a bottom-up traversal of the call tree to apply names, starting from leaf functions and propagating context upwards.

    Such a context-aware approach allows for more accurate and meaningful function naming, especially beneficial in cases where functions 
    interact with external libraries or data, utilize API calls, or contain significant string references. 
    This method aims to propagate as much information as possible upwards through the call tree, ensuring that higher-level functions 
    are named with an understanding of their lower-level interactions.

    Args:
        bv (binaryninja.BinaryView): The binary view containing the functions to be analyzed and renamed.
    """
    # Retrieve the singleton instance of the GPT manager for name suggestions
    gpt = manager_function_name_gpt.get_instance()

    # Collect functions interacting with significant strings and symbols for focused naming
    preselected_functions = collect_symbol_related_functions(
        bv).union(collect_string_related_functions(bv))

    # Iterates through functions in a bottom-up order to apply GPT-based name suggestions, starting with leaves for context propagation.
    # TODO: buttom-up traversal currently disabled due to a bug in the traversal algorithm
    for f in bv.functions:
        # Apply the GPT-based name suggestion to the function if the function is context-enriched and their actual name is not derived
        if f in preselected_functions and not is_derived_func_name(f.name):
            gpt.apply_suggestion(f)


def plugin_wrapper_rename_function_bg(bv, f):
    """
    Initiates a background task to rename a single function using a GPT-based suggestion.

    This function queries a GPT model for a suggested name for the specified function
    and applies the suggestion, aiding in the understanding and analysis of binary code.

    Args:
        bv (binaryninja.BinaryView): The binary view where the function is located.
        f (binaryninja.Function): The function object to be renamed.
    """
    background_task = BGTaskFunction(
        bv,
        "Querying GPT for a function name suggestion and applying it to the selected function.",
        plugin_wrapper_rename_function,
        f
    )
    background_task.start()


def plugin_wrapper_rename_all_functions_bg(bv):
    """
    Initiates a background task to rename all functions in the binary.

    This function leverages a GPT-based naming model to suggest and apply new names
    to every function in the provided binary view, improving the clarity of disassembled code.

    Args:
        bv (binaryninja.BinaryView): The binary view containing the functions to be renamed.
    """
    background_task = BGTask(
        bv,
        "Renaming all functions in the binary based on GPT suggestions.",
        plugin_wrapper_rename_all_functions
    )
    background_task.start()


def plugin_wrapper_context_enriched_function_naming_bg(bv):
    """
    Initiates a background task to enhance function names using context-aware AI suggestions.

    This wrapper function targets the enhancement of function names within the provided binary view,
    employing a context-enriched strategy.

    Args:
        bv (binaryninja.BinaryView): The binary view containing the functions to be analyzed and renamed.
    """
    background_task = BGTask(
        bv,
        "Enhancing function names in the binary with context-aware AI suggestions.",
        plugin_wrapper_context_enriched_function_naming
    )
    background_task.start()
