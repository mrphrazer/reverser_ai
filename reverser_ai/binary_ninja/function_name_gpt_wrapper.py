from binaryninja.settings import Settings

from ..gpt.function_name_gpt import FunctionNameGPT


class FunctionNameGPTWrapper:
    """
    FunctionNameGPTWrapper is a specialized class designed for use with Binary Ninja.
    It leverages the FunctionNameGPT class to generate function name suggestions based on the
    High-Level Intermediate Language (HLIL) decompiler output of functions. This class serves as a bridge between
    Binary Ninja's decompiler output and the FunctionNameGPT's capabilities, allowing automated, AI-driven renaming
    of functions within the Binary Ninja environment based on the analysis of their decompiled code.
    This process facilitates more meaningful and descriptive function names,
    enhancing the readability and comprehensibility of reverse-engineered code.
    """

    def __init__(self):
        """
        Initializes the FunctionNameGPTWrapper instance with a given configuration.
        """
        # Read GPT config from Binary Ninja Settings
        config = self.read_config()
        # Instantiate FunctionNameGPT with user configuration
        self.name_gpt = FunctionNameGPT(config)

    @staticmethod
    def read_config():
        """
        Reads the configuration from Binary Ninja Settings and creates a config dictionary.

        The configuration includes settings for optimizing speed and resource usage by the FunctionNameGPT
        based on the user's hardware capabilities and preferences.

        Returns:
        - dict: A dictionary containing configuration settings read from Binary Ninja.
        """
        config = {}
        # Access each setting using Settings.get and specify the correct setting identifier
        config["use_mmap"] = Settings().get_bool("reverse_ai.use_mmap")
        config["n_threads"] = Settings().get_integer("reverse_ai.n_threads")
        config["n_gpu_layers"] = Settings().get_integer("reverse_ai.n_gpu_layers")
        config["seed"] = Settings().get_integer("reverse_ai.seed")
        config["verbose"] = Settings().get_bool("reverse_ai.verbose")

        return config

    @staticmethod
    def get_hlil_output(f):
        """
        Extracts and returns the HLIL (High-Level Intermediate Language) decompiler output for a given function
        as a string.

        Parameters:
        - f (Function): A BinaryNinja Function object.

        Returns:
        - str: The HLIL decompiler output for the function, formatted as a string.
        """
        # Generate a formatted string from the HLIL lines of the function
        return f"{str(f)}\n" + ''.join(["\t" + line + "\n" for line in map(str, f.hlil.root.lines)])

    def get_function_name_suggestion(self, f):
        """
        Queries NameGPT to obtain a suggested name for a given function based on its HLIL decompiler output.

        Parameters:
        - f (Function): A BinaryNinja Function object.

        Returns:
        - str: The suggested function name.
        """
        # Get HLIL output for the function and query FunctionNameGPT for a name suggestion
        return self.name_gpt.get_function_name_suggestion(f.name, self.get_hlil_output(f))

    def apply_suggestion(self, f):
        """
        Obtains a suggested name for a given function and applies this suggestion to the function
        within Binary Ninja's database.

        Parameters:
        - f (Function): A BinaryNinja Function object to rename.
        """
        # Obtain the suggested name for the function
        suggested_name = self.get_function_name_suggestion(f)
        print(f"Renaming {f.name} to {suggested_name}")
        # Apply the suggested name to the function
        f.name = suggested_name
