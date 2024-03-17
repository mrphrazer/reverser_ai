import os


def get_plugin_directory():
    """
    Returns the directory containing the current plugin script.

    Returns:
        str: The absolute path to the directory containing the plugin script.
    """
    # __file__ gives the path of the current file; os.path.abspath ensures it's absolute.
    current_file_path = os.path.abspath(__file__)
    # os.path.dirname gets the directory containing the file.
    current_directory = os.path.dirname(current_file_path)

    # Use os.path.dirname again on the current directory to get the parent directory -- the plugin directory
    plugin_directory = os.path.dirname(current_directory)

    return plugin_directory
