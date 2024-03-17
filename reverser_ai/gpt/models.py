# Define model identifiers for different types of language model configurations.
# These identifiers are used to specify which pre-trained models to download
# and use for generating function name suggestions based on decompiler output.
# Each key in the dictionary represents a unique model configuration,
# and the associated value is a tuple containing the Hugging Face Hub repository
# and the specific model file name. These models are selected based on their
# performance characteristics and suitability for particular types of analysis.

MODEL_IDENTIFIERS = {
    # "mythomax_13b" is identified for use in scenarios that might involve offensive
    # language or requests. This model is not censored, allowing for a wide range
    # of outputs, including potentially sensitive or offensive content. It is
    # considered "small" in terms of the number of parameters, making it relatively
    # fast for analysis tasks that do not require extensive filtering of output.
    # This model might be suited for research or contexts where content filtering
    # is managed separately.
    "mythomax_13b": ("TheBloke/MythoMax-L2-Kimiko-v2-13B-GGUF", "mythomax-l2-kimiko-v2-13b.Q6_K.gguf"),

    # "mistral-7b-instruct" is optimized for following instructions and performing
    # code analysis tasks. It's a small, fast model designed to quickly process
    # and generate output, e.g., based on the provided programming-related prompts or
    # decompiler outputs. This model is particularly useful for tasks that require
    # understanding and interpreting code or instructions, making it an ideal choice
    # for generating function names from decompiler output. Its performance is
    # tailored to provide a balance between speed and accuracy in such specialized
    # contexts.
    "mistral-7b-instruct": ("TheBloke/Mistral-7B-Instruct-v0.2-GGUF", "mistral-7b-instruct-v0.2.Q4_K_M.gguf")
}
