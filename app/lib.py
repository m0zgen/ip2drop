import os
import subprocess


# Generators for vars
def get_base_dir():
    base = os.path.join(os.getcwd())  # .. means parent directory

    # Return the absolute path of the parent directory
    return os.path.abspath(base)


def up(n, nth_dir=os.getcwd()):
    while n != 0:
        nth_dir = os.path.dirname(nth_dir)
        n -= 1
    print(nth_dir)
    return nth_dir


def get_current_dir():
    return os.path.dirname(os.path.abspath(__file__))


def get_up_dir():
    return os.path.dirname(get_current_dir())


def get_script_dir():
    current = get_current_dir()
    up_dir = os.path.dirname(current)
    return up_dir


def get_parent_directory():
    # Create a relative path to the parent of the current working directory
    relative_parent = os.path.join(os.getcwd(), "..")  # .. means parent directory
    # Return the absolute path of the parent directory
    return os.path.abspath(relative_parent)


# Command operators
def bash_command(cmd):
    subprocess.Popen(cmd, shell=True, executable='/bin/bash')


def bash_cmd(cmd):
    subprocess.Popen(['/bin/bash', '-c', cmd])
    # print(f'CMD: {cmd}')


# Expiremental

# Ad id to filename, like as dato for log rotate
# Ref: https://stackoverflow.com/questions/37487758/how-to-add-an-id-to-filename-before-extension
def append_id(filename):
    name, ext = os.path.splitext(filename)
    result = "{name}_{uid}{ext}".format(name=name, uid=TODAY.strftime("%d_%m_%Y"), ext=ext)
    # msg_info(f'Result: {result}')
    return result


get_script_dir()
up
