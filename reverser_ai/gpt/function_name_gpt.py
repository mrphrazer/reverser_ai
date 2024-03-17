from .agent import LLM_Agent
from .models import MODEL_IDENTIFIERS


class FunctionNameGPT:
    """
    FunctionNameGPT facilitates querying a local Large Language Model (LLM) to suggest function names based on
    decompiler output. This functionality is particularly useful in the context of reverse engineering, where accurate
    and meaningful function names can significantly enhance the readability and understanding of disassembled code.
    Decompiler output from tools like Ghidra, Binary Ninja, or IDA Pro can be fed into this class to

    generate suggestions. The parameters used for querying the LLM are empirically determined
    to offer a balanced trade-off between the quality of the suggestions and the analysis time required.
    """

    def __init__(self, config):
        """
        Initializes the FunctionNameGPT instance with specific configurations for querying the LLM model.

        The configuration includes selecting the appropriate model from MODEL_IDENTIFIERS, setting
        a context limit, and defining generation parameters aimed at optimizing the name suggestion process.

        Parameters:
        - config (dict): A configuration dictionary to be passed to the LLM_Agent.
        """
        # Overrides specific configuration settings for FunctionNameGPT usage
        # Model identifier for the LLM
        config['model_identifier'] = MODEL_IDENTIFIERS["mistral-7b-instruct"]
        # Context length limit to manage large functions
        config['n_context'] = 4000

        # Define generation kwargs with empirically determined values for optimal performance
        config['generation_kwargs'] = {
            # Limit model output to prevent overly verbose responses
            "max_tokens": 5000,
            # Token indicating the end of the model's output
            "stop": ["</s>"],
            # Minimum probability threshold for token generation
            "min_p": 0.1,
            # Sampling temperature for diversity
            "temperature": 0.8,
            # Penalty for repeated token generation to encourage diversity
            "repeat_penalty": 1,
        }

        # Instantiate LLM_Agent with the modified configuration
        self.agent = LLM_Agent(config)

    def build_prompt(self, code):
        """
        Constructs a custom prompt tailored for querying the LLM to suggest function names based on decompiler output.

        Parameters:
        - code (str): The decompiler output for a given function.

        Returns:
        - str: A formatted prompt for the LLM including the instruction and the decompiled code.
        """
        # Constructing a detailed prompt to guide the LLM in generating a suitable function name
        user_prompt = (
            f"<s>[INST]Given the following decompiler output for a function, "
            f"analyze its operations, logic, and any identifiable patterns to suggest a suitable function name. "
            f"Your response should strictly be the function name suggestion and up to 20 characters. "
            f"Discard all explanations or content, only the suggested name.[/INST] add_two_values</s> "
            f"[INST]Here's the code:\n {code}[/INST]"
        )
        return self.agent.build_prompt(user_prompt)

    def query_gpt_for_function_name_suggestion(self, code):
        """
        Directly queries the GPT model for a function name suggestion based on the provided decompiler output.

        Parameters:
        - code (str): The decompiler output for a given function.

        Returns:
        - The raw output from the LLM model as a response to the query.
        """
        # Passes the custom prompt to the LLM_Agent and returns the raw response
        return self.agent.generate_response(self.build_prompt(code))

    def get_function_name_suggestion(self, original_name, code):
        """
        Attempts to get a function name suggestion from the LLM. If the suggestion process fails
        (e.g., due to the code being too long), it returns the original function name.

        Parameters:
        - original_name (str): The original function name, used as a fallback.
        - code (str): The decompiler output for the function.

        Returns:
        - str: The suggested function name or the original name if suggestion fails.
        """
        try:
            # Attempts to query the LLM for a name suggestion and filter the output
            return self.filter_output(self.query_gpt_for_function_name_suggestion(code))
        except:
            # Fallback to the original name in case of any errors
            return original_name

    @staticmethod
    def filter_output(output):
        """
        Cleans the model's response by removing any additional explanations and normalizing the function name format.
        Specifically, it ensures function names containing underscores are correctly formatted without
        escape characters.

        Parameters:
        - output (str): The raw model output containing the function name suggestion.

        Returns:
        - str: The filtered and normalized function name.
        """
        # Process the model's output to extract and normalize the function name
        filtered_output = output.strip().split(
            "\n")[0].strip().replace("\\_", "_")
        return filtered_output
