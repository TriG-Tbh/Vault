#!/usr/bin/env python3

import functions
import getpass
import os
import requests
import shutil

import platform
windows = (platform.system() == "Windows")

def main():
    functions.clear()
    if not functions.exists():
        try:
            functions.intro()
        except KeyboardInterrupt:
            functions.clear()
            import sys
            sys.exit(0)
    functions.clear()
    try:
        password = getpass.getpass("Password: ")
    except KeyboardInterrupt:
        functions.clear()
        import sys
        sys.exit(0)
    goahead = functions.login(password)
    if not goahead:
        functions.clear()
        print("Invalid password")
        import sys
        sys.exit(1)
    while True:
        functions.clear()
        print("Vault")
        print("Use Ctrl+C to return back to this menu, or use it here to exit.\n")
        try:
            action = input(
                "1: Encrypt a file\n2: Download and encrypt a file from a URL\n3: Decrypt a file\n4: Change password\nSelect an option: ")
        except:
            break
        action = action.strip().lstrip()
        try:
            action = int(action)
        except:
            continue
        if action not in [1, 2, 3, 4]:
            continue
        if action == 1:
            functions.clear()
            try:
                path = input("Please specify a file to encrypt: ")
            except KeyboardInterrupt:
                continue
            if functions.validate(path) and not path.endswith(".png"):
                functions.clear()
                try:
                    response = input(
                        "This file may be a valid image file. Convert to .png (y/n)? ")
                except KeyboardInterrupt:
                    continue
                if response.lower().lstrip().strip() == "y":
                    temp = path
                    path = functions.convert(path)
                    delete = input("Delete original file (y/n)? ")
                    if delete.lower().lstrip().strip() == "y":
                        if not windows:
                            temp = temp.replace("\\", "")
                        try:
                            directory = os.path.dirname(os.path.realpath(temp))
                            os.chdir(directory)
                            os.remove(temp)
                        except:
                            pass
            functions.clear()
            try:
                save = functions.encodepath(path)
                if save == None:
                    continue
            except Exception as e:
                print(str(e))
                try:
                    input("Invalid file path. Press enter to continue. ")
                except KeyboardInterrupt:
                    continue
                continue
            else:
                try:
                    input(
                        "File encrypted.\nEncrypted file path: {}\nPress enter to continue. ".format(save))
                except KeyboardInterrupt:
                    continue
                continue

        elif action == 2:
            functions.clear()
            try:
                url = input("Please specify a file URL to download: ")
            except KeyboardInterrupt:
                continue

            name = os.path.split(url)[-1]
            base = os.path.dirname(os.path.realpath(__file__))
            path = os.path.join(base, name)
            functions.clear()

            try:
                r = requests.get(url, stream=True)
                with open(path, 'wb') as out_file:
                    shutil.copyfileobj(r.raw, out_file)
            except:
                try:
                    input("Invalid URL: {}\nPress enter to continue. ".format(url))
                except KeyboardInterrupt:
                    continue
                continue
            if functions.validate(path) and not path.endswith(".png"):
                functions.clear()
                try:
                    response = input(
                        "This file may be a valid image file. Convert to .png (y/n)? ")
                except KeyboardInterrupt:
                    continue
                if response.lower().lstrip().strip() == "y":
                    temp = path
                    path = functions.convert(path)
                    delete = input("Delete original file (y/n)? ")
                    if delete.lower().lstrip().strip() == "y":
                        if not windows:
                            temp = temp.replace("\\", "")
                        try:
                            directory = os.path.dirname(os.path.realpath(temp))
                            os.chdir(directory)
                            os.remove(temp)
                        except:
                            pass
            functions.clear()
            try:
                save = functions.encodepath(path)
            except:
                try:
                    input("Invalid file path. Press enter to continue. ")
                except KeyboardInterrupt:
                    continue
                continue
            else:
                try:
                    input(
                        "File encrypted.\nEncrypted file path: {}\nPress enter to continue. ".format(save))
                except KeyboardInterrupt:
                    continue
                continue
        elif action == 3:
            functions.clear()
            try:
                path = input("Please specify a .enc file to decrypt: ")
            except KeyboardInterrupt:
                continue
            functions.clear()
            try:
                save = functions.decodepath(path)
            except Exception as e:
                print(str(e))
                try:
                    input("Invalid file path. Press enter to continue. ")
                except KeyboardInterrupt:
                    continue
                continue
            else:
                try:
                    input(
                        "File decrypted.\nDecrypted file path: {}\nPress enter to continue. ".format(save))
                except KeyboardInterrupt:
                    continue
                continue
        elif action == 4:
            try:
                functions.clear()
                current = input("Current password: ")
                if current != password:
                    input("Passwords do not match. Press enter to continue. ")
                    continue
                new = input("New password: ")
                confirm = input(
                    "You will need to decrypt all files with your old password. Your new password will not be able to decrypt already encrypted files.\nRetype your password to confirm: ")
                if confirm != new:
                    input("Passwords do not match. Press enter to continue. ")
                    continue
                functions.writepw(new)
                functions.clear()
                input("Password changed to: {}.\nPress enter to continue. ".format(new))
            except KeyboardInterrupt:
                continue


    functions.clear()

if __name__ == "__main__":
    main()
