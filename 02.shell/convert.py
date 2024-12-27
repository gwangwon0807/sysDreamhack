#! /usr/bin/python3

file_path = "./write.bin"

with open(file_path, "rb") as file:
    machine_code = file.read()
    for byte in machine_code:
            print("\\x{:02x}".format(byte), end="")

print()
