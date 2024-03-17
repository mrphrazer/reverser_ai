from huggingface_hub import hf_hub_download
from llama_cpp import Llama


class LLM_Agent:
    """
    The LLM_Agent class serves as a generic agent to facilitate interactions with local GPT models, specifically
    leveraging the Llama library for model operations. This class abstracts away the complexity of model initialization,
    prompt generation, and response handling, providing a simplified interface for GPT model interactions.

    It is designed to be configurable, allowing users to specify model parameters such as context size, threading,
    GPU layer usage, and more through a configuration dictionary passed at initialization.
    This design promotes flexibility and adaptability to different model requirements and usage scenarios.
    """

    def __init__(self, config):
        """
        Initializes the LLM agent with a configuration dictionary. This configuration
        must specify all the necessary parameters for the LLM model setup, including
        the seed for reproducibility.

        Parameters:
        - config (dict): Configuration dictionary containing model settings.
        """
        # Number of tokens for the context window
        self.n_context = config['n_context']
        # Use memory mapping for model loading
        self.use_mmap = config['use_mmap']
        # Number of CPU threads to utilize
        self.n_threads = config['n_threads']
        # Number of model layers to offload to GPU
        self.n_gpu_layers = config['n_gpu_layers']
        # Model identifier for downloading
        self.model_identifier = config['model_identifier']
        # Seed for model initialization
        self.seed = config['seed']
        # Verbosity level
        self.verbose = config['verbose']
        # Generation kwargs to define model inference options
        self.generation_kwargs = config['generation_kwargs']

        # Downloading the model and getting its local path
        self.model_path = self.get_model_path(self.model_identifier)

        # Instantiating the Llama model with specified configuration
        self.llm = Llama(
            model_path=self.model_path,
            use_mmap=self.use_mmap,
            n_ctx=self.n_context,
            n_threads=self.n_threads,
            n_gpu_layers=self.n_gpu_layers,
            seed=self.seed,
            verbose=self.verbose,
        )

    @staticmethod
    def get_model_path(model_identifier):
        """
        Downloads the model from Hugging Face Hub based on the identifier and returns its local path.

        Parameters:
        - model_identifier (tuple): A tuple of the model's name and filename on Hugging Face Hub.

        Returns:
        - str: Local file path to the downloaded model.
        """
        model_name, model_file = model_identifier
        return hf_hub_download(model_name, filename=model_file)

    @staticmethod
    def build_prompt(user_prompt):
        """
        Constructs a model prompt from the user input.

        Parameters:
        - user_prompt (str): The initial prompt provided by the user.

        Returns:
        - str: A string containing the constructed prompt.
        """
        return f"{user_prompt}\n### Response:"

    def generate_response(self, user_prompt):
        """
        Generates a response from the LLM based on the user's prompt and generation parameters.

        Parameters:
        - user_prompt (str): The user's prompt to the model.

        Returns:
        - str: Raw model output.
        """
        prompt = self.build_prompt(user_prompt)
        res = self.llm(prompt, **self.generation_kwargs)
        return res["choices"][0]["text"]
