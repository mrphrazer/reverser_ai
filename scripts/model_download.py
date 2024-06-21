from reverser_ai.gpt.function_name_gpt import FunctionNameGPT


def initiate_download():
    """
    Triggers the download of the GPT model file by initializing the FunctionNameGPT model with a specific configuration.

    This function sets up a minimal configuration that disables the usage of memory mapping (mmap), CPU threads, and GPU layers
    to trigger the model file download without intending for actual model execution. This setup is useful for pre-downloading the model
    file in environments where direct model execution is not the goal, such as preparing a deployment environment or caching the model
    file in advance. It is recommended not to use this configuration for executing the model in typical application scenarios due to
    the disabled computational resources.

    The `verbose` mode is enabled to provide detailed output during the model download process, offering insights into the download progress
    and any potential issues encountered.
    """
    # Define the configuration for the model download
    config = {
        # Select model to download: `mistral-7b-instruct` or `mixtral-8x7b-instruct`.
        'model_identifier': "mistral-7b-instruct",
        # Enables partial on-demand loading of the model into memory using mmap
        'use_mmap': False,
        # Sets the number of CPU threads to 0, effectively disabling CPU processing
        'n_threads': 0,
        # Sets the number of GPU layers to 0, disabling GPU processing
        'n_gpu_layers': 0,
        # Specifies an initial seed for model operations, required but not used in this context
        'seed': 0,
        # Enables verbose output to monitor the download and initialization process
        'verbose': True,
    }

    # Initialize the FunctionNameGPT model with the above configuration to trigger the model file download
    gpt = FunctionNameGPT(config)


# Call the function to start the model file download process
initiate_download()
