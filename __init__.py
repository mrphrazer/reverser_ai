from binaryninja import PluginCommand
from binaryninja.settings import Settings

from .reverser_ai.binary_ninja import (
    plugin_wrapper_context_enriched_function_naming_bg,
    plugin_wrapper_rename_all_functions_bg,
    plugin_wrapper_rename_function_bg,
)

'''
Plugin Commands
'''
PluginCommand.register_for_function(
    "ReverserAI\\Rename Current Function",
    "Renames the selected function with an AI-generated suggestion.",
    plugin_wrapper_rename_function_bg
)

PluginCommand.register(
    "ReverserAI\\Rename All Functions",
    "Renames all functions using AI-generated suggestions.",
    plugin_wrapper_rename_all_functions_bg
)


PluginCommand.register(
    "ReverserAI\\Enhance Function Naming with Context",
    "Enhances function names using context-aware AI-generated suggestions for better accuracy and relevance.",
    plugin_wrapper_context_enriched_function_naming_bg
)


'''
Plugin Settings
'''
Settings().register_group(
    "reverser_ai",
    "ReverserAI"
)


Settings().register_setting(
    "reverser_ai.use_mmap",
    '''
    {
        "description" : "Optimize speed by loading the entire model into memory (requires ~5GB RAM for the default model).", 
        "title" : "Use Memory Mapping", 
        "default" : true, 
        "type" : "boolean",
        "requiresRestart": true
    }
    '''
)

Settings().register_setting(
    "reverser_ai.n_threads",
    '''
    {
        "description" : "Utilize CPU threads; set to 0 to disable CPU. For full CPU load, set to maximum number of available threads.", 
        "title" : "Number of CPU Threads", 
        "default" : 0, 
        "type" : "number",
        "requiresRestart": true
    }
    '''
)

Settings().register_setting(
    "reverser_ai.n_gpu_layers",
    '''
    {
        "description" : "Utilize GPU layers for faster processing with a strong GPU.", 
        "title" : "Number of GPU Layers", 
        "default" : 99,
        "type" : "number",
        "requiresRestart": true
    }
    '''
)

Settings().register_setting(
    "reverser_ai.seed",
    '''
    {
        "description" : "Ensure deterministic model outputs by specifying a seed.", 
        "title" : "Seed for Determinism", 
        "default" : 0, 
        "type" : "number",
        "requiresRestart": true
    }
    '''
)

Settings().register_setting(
    "reverser_ai.verbose",
    '''
    {
        "description" : "Toggle verbose logging of model configurations.", 
        "title" : "Verbose Model Logging", 
        "default" : false, 
        "type" : "boolean",
        "requiresRestart": true
    }
    '''
)

Settings().register_setting(
    "reverser_ai.model_identifier",
    '''
    {
        "description": "Select the model to use for inference. Each model has distinct capabilities and resource requirements.",
        "title": "Model Identifier",
        "type": "string",
        "enum": [
            "mistral-7b-instruct",
            "mixtral-8x7b-instruct"
        ],
        "enumDescriptions": [
            "A small, fast model, requiring ~5GB RAM. Ideal for quick processing and generating function names, although it has a reduced quality in outputs compared to larger models.",
            "A larger model, requiring ~45GB RAM. Offers enhanced reasoning capabilities and accuracy at the cost of higher resource usage. Disabling memory mapping might be necessary on machines not capable of supporting the required RAM level."
        ],
        "default": "mistral-7b-instruct",
        "requiresRestart": true
    }
    '''
)
