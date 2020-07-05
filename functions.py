
import platform
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import hashlib
import PIL
from PIL import Image
from cryptography import fernet
import shutil

salt = b'\x9c\x06"\xb2\xb6\xb7\x91\x06!b\xa1\x89\xa8\x83\x89\xec'

windows = (platform.system() == "Windows")

kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                 length=32,
                 salt=salt,
                 iterations=100000,
                 backend=default_backend())


def clear():
    import platform
    plt = platform.system()
    if plt == "Linux" or plt == "Darwin":
        os.system("clear")
    elif plt == "Windows":
        os.system("cls")
    else:
        pass


def intro():
    input("Welcome to Vault!\nVault encrypts and decrypts the contents of files with a given password.\nIn order to begin, you will need to set a password.\nThis password will be used to both encrypt and decrypt files. Make sure you don't forget it!\nPress enter to continue. ")
    clear()
    password = input("Enter a password: ")
    confirm = input("Confirm your password by typing it again: ")
    if password != confirm:
        print("Password not confirmed. Please run this script again.")
        import sys
        sys.exit(1)
    writepw(password)
    clear()
    input("Password set. Press enter to continue. ")


def join(name):
    path = os.path.dirname(__file__)
    return os.path.join(path, name)


def exists():
    try:
        with open(join("password.txt"), "r") as _:
            pass
    except:
        return False
    return True


def login(password_provided):
    password = password_provided.encode()
    hash_object = hashlib.md5(str.encode(password_provided))
    hashed = hash_object.hexdigest()

    if os.path.exists(join("password.txt")):
        with open(join("password.txt")) as f:
            hashed_pw = f.read()
    else:
        clear()
        print("Error reading password. Please set your password again by re-running the script.")
        import sys
        sys.exit(1)

    if hashed != hashed_pw:
        return False
    global key, fernet
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fernet = Fernet(key)
    return True


def writepw(password_provided):
    hash_object = hashlib.md5(str.encode(password_provided))
    hashed = hash_object.hexdigest()

    with open(join("password.txt"), "w") as f:
        f.write(str(hashed))


def encodepath(path, delete=True):

    path = sanitize(path)
    if os.path.isdir(path):
        zipfolder = "n"
        try:
            zipfolder = input(
                "The file specified is a folder. Would you like to turn it into a .zip file and encrypt it (y/n)? ")
            if zipfolder.strip().lstrip().lower() != "y":
                return None
            shutil.make_archive(path, 'zip', path)
            shutil.rmtree(path)
            clear()
            saved = encodepath(path + '.zip')
            return saved
        except KeyboardInterrupt:
            return None

    name = os.path.split(path)[-1]
    try:
        extension = "." + ".".join(name.split(".")[1:])
    except:
        extension = ""
    directory = os.path.dirname(path)
    os.chdir(directory)
    savepath = os.path.join(directory, name)
    savepath = savepath[:-len(extension)] + ".enc"
    with open(path, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)
    with open(savepath, "wb") as f:
        f.write(encrypted)

    with open(savepath, "a") as f:
        f.write("|" + extension)

    if delete:
        os.remove(path)
    return savepath


def sanitize(path):
    if not windows:
        path = path.replace("\\", "")
    if windows:
        if path.startswith("& '") and path.endswith("'"):
            path = path[3:-1]
    return path


def decodepath(path, delete=True):
    path = sanitize(path)
    directory = os.path.dirname(path)
    os.chdir(directory)
    name = os.path.split(path)[-1]

    with open(path, "r") as f:
        text = f.read()

    name = name[:-4]
    if "|" not in text:
        savepath = os.path.join(directory, name)
    else:
        extension = text.split("|")[-1]
        savepath = os.path.join(directory, name)
        savepath = savepath + extension
        with open(path, "w") as f:
            f.write("|".join(text.split("|")[:-1]))
    with open(path, "rb") as f:
        data = f.read()

    with open(path, "a") as f:
        f.write("|{}".format(extension))

    decrypted = fernet.decrypt(data)
    with open(savepath, "wb") as f:
        f.write(decrypted)

    if delete:
        os.remove(path)

    return savepath


def validate(path):
    path = sanitize(path)
    try:
        _ = Image.open(path)
    except:
        return False
    return True


def convert(path):
    path = sanitize(path)
    im = Image.open(path)
    try:
        im.convert("RGBA")
    except:
        return
    name = ".".join(path.split(".")[:-1])
    im.save(name + ".png", "png")
    return name + ".png"
