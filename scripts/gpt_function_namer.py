from reverser_ai.gpt.function_name_gpt import FunctionNameGPT
from reverser_ai.config import load_user_config
import sys

def generate_xor_c_function():
    """
    Generates and returns a string containing the source code of a C function named 'example'.
    This function takes two unsigned int parameters and returns their XOR result. The style and
    format of the generated code are designed to resemble decompilation output from the Ghidra
    reverse engineering tool, aiding in understanding how such code might appear in a decompiler's output.

    Returns:
        str: The source code of the C function as a string.
    """
    c_code = """
            unsigned int example(unsigned int param_1, unsigned int param_2)
            {
                unsigned int result;
                result = param_1 ^ param_2;
                return result;
            }
            """
    return c_code

def main():
    """
    Main function that orchestrates the generation of a C function, loading of user configuration,
    initialization of the GPT model, and obtaining a suggested function name based on the generated C code.

    Expects a command-line argument specifying the path to the user configuration file.
    The script will terminate with an error message if the configuration file path is not provided.
    """
    # Verify that the script is called with the required number of arguments
    if len(sys.argv) < 2:
        print("Error: Missing argument. Please provide the path to the configuration file.")
        sys.exit(1)

    # Read configuration path from command-line arguments
    config_path = sys.argv[1]

    # Load user configuration from the specified path
    config = load_user_config(config_path)

    # Initialize the FunctionNameGPT model with the loaded configuration
    gpt = FunctionNameGPT(config)

    # Generate the C function code
    c_function_code = generate_xor_c_function()

    # Let the GPT model suggest a function name based on the generated C code
    suggested_name = gpt.get_function_name_suggestion("example", c_function_code)

    # Print the suggested function name
    print(f"Suggested name: {suggested_name}")

if __name__ == "__main__":
    main()
