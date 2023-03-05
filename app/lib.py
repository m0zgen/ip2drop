import os

# Generators
def get_base_dir():
    base = os.path.join(os.getcwd())  # .. means parent directory

    # Return the absolute path of the parent directory
    return os.path.abspath(base)


def get_current_dir():
    return os.path.dirname(os.path.abspath(__file__))


def get_parent_directory():
    # Create a relative path to the parent of the current working directory
    relative_parent = os.path.join(os.getcwd(), "..")  # .. means parent directory

    # Return the absolute path of the parent directory
    return os.path.abspath(relative_parent)