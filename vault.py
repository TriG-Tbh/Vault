#!/usr/bin/env python3

import argparse
import base64
import errno
import getpass
import hashlib
import logging
import os
import secrets
import sys
import tempfile
from urllib.parse import urlsplit
try:
    import winreg
except ImportError:
    pass
import zipfile

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import requests


__PROG__ = 'vault'
__AUTHORS__ = ('TriG-Tbh', 'Dogeek')
__version__ = (1, 0, 0)


logger = logging.getLogger(__name__)


def ask_password():
    confirm = ''
    password = '0'
    while confirm != password:
        password = getpass.getpass('Enter your password : ')
        confirm = getpass.getpass('Confirm your password : ')
    return password


def create_new_key(password, salt):
    print('Creating a new key')
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**12,
        r=8,
        p=1,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf8'))).decode('ascii')
    print('Generated key : %s' % key)

    if sys.platform.startswith('win'):
        key_path = 'SOFTWARE\\' + __PROG__.capitalize()
        try:
            winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            registry_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, key_path,
                0, winreg.KEY_WRITE,
            )
            winreg.SetValueEx(registry_key, 'key', 0, winreg.REG_SZ, key)
        except WindowsError:
            raise
    else:
        key_path = os.path.join(os.path.expanduser('~/.config'), __PROG__.capitalize())
        with open(os.path.join(key_path, 'key'), 'w') as file_handler:
            file_handler.write(key)


def create_new_password(generate_key=False):
    password = ask_password()
    salt = secrets.token_bytes(16)
    password = hashlib.blake2b(
        password.encode('utf8'), salt=salt,
        person=getpass.getuser().encode('utf8'),
    ).hexdigest()
    salt = base64.b64encode(salt).decode('ascii')

    if sys.platform.startswith('win'):
        pass_path = 'SOFTWARE\\' + __PROG__.capitalize()
        try:
            winreg.CreateKey(winreg.HKEY_CURRENT_USER, pass_path)
            registry_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, pass_path,
                0, winreg.KEY_WRITE,
            )
            winreg.SetValueEx(registry_key, 'password', 0, winreg.REG_SZ, password)
            winreg.SetValueEx(registry_key, 'salt', 0, winreg.REG_SZ, salt)
        except WindowsError:
            raise
    else:
        pass_path = os.path.join(os.path.expanduser('~/.config'), __PROG__.capitalize())
        os.makedirs(pass_path, exist_ok=True)
        with open(os.path.join(pass_path, 'password'), 'w') as f:
            f.write(password)
        with open(os.path.join(pass_path, 'salt'), 'w') as f:
            f.write(salt)

    if generate_key:
        create_new_key(password, base64.b64decode(salt))

    return password, salt, True


def get_stored_password():
    if sys.platform.startswith('win'):
        pass_path = 'SOFTWARE\\' + __PROG__.capitalize()
        try:
            registry_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, pass_path,
                0, winreg.KEY_READ,
            )
            password, regtype = winreg.QueryValueEx(registry_key, 'password')
            salt, regtype = winreg.QueryValueEx(registry_key, 'salt')
            salt = base64.b64decode(salt)
            winreg.CloseKey(registry_key)
            return password, salt, False
        except FileNotFoundError:
            return create_new_password(generate_key=True)
    else:
        pass_path = os.path.join(os.path.expanduser('~/.config'), __PROG__.capitalize())
        try:
            with open(os.path.join(pass_path, 'password'), 'r') as f:
                password = f.read()
            with open(os.path.join(pass_path, 'salt'), 'r') as f:
                salt = f.read()
                salt = base64.b64decode(salt)
            return password, salt, False
        except FileNotFoundError:
            return create_new_password(generate_key=True)


def get_encryption_key():
    if sys.platform.startswith('win'):
        key_path = 'SOFTWARE\\' + __PROG__.capitalize()
        registry_key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, key_path,
            0, winreg.KEY_READ,
        )
        key, regtype = winreg.QueryValueEx(registry_key, 'key')
        winreg.CloseKey(registry_key)
    else:
        key_path = os.path.join(os.path.expanduser('~/.config'), __PROG__.capitalize())
        with open(os.path.join(key_path, 'key'), 'r') as f:
            key = f.read()
    return key.encode('ascii')


def get_version():
    return f"{__PROG__} by {', '.join(a for a in __AUTHORS__)} v{'.'.join(str(v) for v in __version__)}"


def login(password=None, tries=3):
    stored_pass, salt, logged_in = get_stored_password()
    if logged_in:
        fernet = Fernet(get_encryption_key())
        return fernet
    for i in range(tries + 1):
        if i == 0 and password is None:
            continue
        if i > 0:
            password = getpass.getpass('Password: ')
        password = hashlib.blake2b(
            password.encode('utf8'), salt=salt,
            person=getpass.getuser().encode('utf8'),
        ).hexdigest()
        if secrets.compare_digest(password, stored_pass):
            fernet = Fernet(get_encryption_key())
            return fernet
        print('Incorrect password, try again.')
    return False


def encrypt(key=None, fernet=None, path=None, url=None, delete=None):
    logger.info('Starting to encrypt %s...', str(path))
    if url:
        logger.info('URL flag passed, trying to download the file...')
        file_handler = tempfile.NamedTemporaryFile('wb')
        try:
            data = requests.get(path).raw
        except requests.RequestException as e:
            logger.exception(str(e))
            raise
        file_handler.write(data)
        filename = urlsplit(path).path.split('/')[-1]
        path = os.path.join(os.getcwd(), filename)
    elif os.path.isdir(path):
        logger.info('Directory detected, zipping the directory to encrypt it...')
        delete = True
        filename = os.path.split(path)[-1] + '.zip'

        file_handler = zipfile.ZipFile(
            os.path.join(path, filename), 'w',
            compression=zipfile.ZIP_LZMA,
        )
        for root, dirs, files in os.walk(path):
            for file_ in files:
                file_handler.write(os.path.join(root, file_))
        file_handler.close()
        path = os.path.join(path, filename)
        file_handler = open(path, 'rb')
    else:
        file_handler = open(path, 'rb')
        filename = os.path.split(path)[-1]

    directory = os.path.dirname(path)
    if directory:
        print('Changing path to directory %s' % directory)
        os.chdir(directory)
    savepath = os.path.join(directory, filename + '.enc')
    logger.info('The file will be saved to %s', savepath)
    data = file_handler.read()
    file_handler.close()
    encrypted = fernet.encrypt(data)
    logger.info('File encrypted, now saving...')

    with open(savepath, "wb") as file_handler:
        file_handler.write(encrypted)

    if delete:
        logger.info('Delete flag passed, deleting %s', path)
        os.remove(path)
    return 0


def decrypt(key=None, fernet=None, path=None, delete=None):
    if not path.endswith('.enc'):
        return errno.EBADF

    directory = os.path.dirname(path)
    if directory:
        print('Changing path to directory : %s' % directory)
        os.chdir(directory)
    filename = os.path.split(path)[-1]

    with open(path, 'rb') as file_handler:
        data = file_handler.read()

    with open(os.path.splitext(path)[0], 'wb') as file_handler:
        file_handler.write(fernet.decrypt(data))

    if delete:
        os.remove(path)
    return 0


def change_password(fernet=None, generate_key=False):
    if generate_key:
        print('This will render your already encrypted files undecypherable.')
        confirm = input('Are you sure (y/N)?  ')
        if confirm.lower().startswith('n') or not confirm:
            generate_key = False
            logger.info('Key will not be regenerated.')
    try:
        create_new_password(generate_key=generate_key)
    except Exception as e:
        logger.exception(str(e))
        raise

    return 0


def main():
    parser = argparse.ArgumentParser(prog=__PROG__)
    parser.add_argument('--version', action='version', version=get_version())
    parser.add_argument('--password', '-p', type=str, help='Password to encrypt/decrypt files')

    subparsers = parser.add_subparsers()

    encrypt_parser = subparsers.add_parser('encrypt')
    encrypt_parser.add_argument('path')
    encrypt_parser.add_argument('--url', '-u', action='store_true', help='Specify an URL instead of a path')
    encrypt_parser.add_argument('--delete', '-d', action='store_true', help='Delete the original file')
    encrypt_parser.set_defaults(callback=encrypt)

    decrypt_parser = subparsers.add_parser('decrypt')
    decrypt_parser.add_argument('path')
    decrypt_parser.add_argument('--delete', '-d', action='store_true', help='Delete the original file')
    decrypt_parser.set_defaults(callback=decrypt)

    password_parser = subparsers.add_parser('pass')
    password_parser.add_argument('--generate_key', '-k', action='store_true', help='Regenerates the encryption key')
    password_parser.set_defaults(callback=change_password)

    args = vars(parser.parse_args())

    fernet = login(args.pop('password', None))
    if not fernet:
        print('Error while logging in...')
        return errno.EPERM

    callback = args.pop('callback')
    args.update({'fernet': fernet})
    return callback(**args)


if __name__ == '__main__':
    sys.exit(main())
