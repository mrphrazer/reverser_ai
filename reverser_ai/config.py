import toml


def load_user_config(config_path):
    """
    Loads and parses a TOML configuration file.

    This function reads a TOML file specified by the `config_path` parameter
    and parses it into a Python dictionary.

    Args:
        config_path (str): The path to the TOML configuration file.

    Returns:
        dict: The configuration settings parsed from the TOML file, represented as a dictionary.
    """
    # Open and read the TOML configuration file
    with open(config_path, 'r') as config_file:
        # Use the toml library to parse the file into a Python dictionary
        config = toml.load(config_file)
    # Return the parsed configuration
    return config
