import os
import hashlib
import json
import threading
import requests
from flask import Flask
from fastapi import FastAPI
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, RIPEMD160
from Crypto.Signature import pkcs1_15
import socket
import random
import base64
import zlib
import time
import datetime
import logging
import csv
import xml.etree.ElementTree as ET
import sqlite3
import re

class ObsidianScript:
    def __init__(self):
        self.env_variables = {}
        self.native_functions = {}
        self.execution_logs = []
        self.imported_modules = {}
        self.task_queue = []

    def display(self, text):
        print(text)

    def show(self, var_name):
        if var_name in self.env_variables:
            print(self.env_variables[var_name])
        else:
            print(f"Variable {var_name} not found")

    def record(self, message):
        self.execution_logs.append(message)
        print(f"Record: {message}")

    def import_module(self, module_name):
        if module_name == 'socket':
            self.imported_modules['socket'] = socket
        elif module_name == 'requests':
            self.imported_modules['requests'] = requests
        elif module_name == 'hashlib':
            self.imported_modules['hashlib'] = hashlib
        elif module_name == 'json':
            self.imported_modules['json'] = json
        elif module_name == 'threading':
            self.imported_modules['threading'] = threading
        elif module_name.startswith('crypto.'):
            crypto_lib = module_name.split('.')[1]
            if crypto_lib == 'aes':
                self.imported_modules['crypto.aes'] = AES
            elif crypto_lib == 'rsa':
                self.imported_modules['crypto.rsa'] = RSA
            else:
                print(f"Crypto library {crypto_lib} is not available")
        elif module_name == 'web.framework':
            self.imported_modules['web.framework'] = Flask
        elif module_name == 'restapi':
            self.imported_modules['restapi'] = FastAPI
        elif module_name == 'randomizer':
            self.imported_modules['randomizer'] = random
        elif module_name == 'base64':
            self.imported_modules['base64'] = base64
        elif module_name == 'compression':
            self.imported_modules['compression'] = zlib
        elif module_name == 'clock':
            self.imported_modules['clock'] = time
        elif module_name == 'timestamp':
            self.imported_modules['timestamp'] = datetime
        elif module_name == 'logger':
            self.imported_modules['logger'] = logging
        elif module_name == 'csv_tools':
            self.imported_modules['csv_tools'] = csv
        elif module_name == 'xml_tools':
            self.imported_modules['xml_tools'] = ET
        elif module_name == 'sqlite':
            self.imported_modules['sqlite'] = sqlite3
        elif module_name == 'regex':
            self.imported_modules['regex'] = re
        else:
            print(f"Module {module_name} is not available")

    def clone_variable(self, var_name):
        if var_name in self.env_variables:
            self.env_variables[f"{var_name}_clone"] = self.env_variables[var_name]
        else:
            print(f"Variable {var_name} not found")

    def execute(self, file_path):
        if file_path.endswith('.hy'):
            self.run_script(file_path)
        else:
            print(f"File type for {file_path} not supported")

    def conditional(self, condition, then_block, else_block=None):
        if condition:
            self.execute_block(then_block)
        elif else_block:
            self.execute_block(else_block)

    def run_script(self, file_path):
        with open(file_path, 'r') as file:
            script_code = file.read()
            self.execute_code(script_code)

    def execute_block(self, block):
        for line in block:
            self.execute_line(line)

    def execute_line(self, line):
        parts = line.split()
        command = parts[0]
        arguments = parts[1:]

        if command == 'display':
            self.display(' '.join(arguments))
        elif command == 'show':
            self.show(arguments[0])
        elif command == 'record':
            self.record(' '.join(arguments))
        elif command == 'include':
            self.import_module(arguments[0])
        elif command == 'clone':
            self.clone_variable(arguments[0])
        elif command == 'execute':
            self.execute(arguments[0])
        elif command == 'conditional':
            condition = eval(' '.join(arguments[:-2]))
            then_block = arguments[-2]
            else_block = arguments[-1] if len(arguments) > 1 else None
            self.conditional(condition, then_block, else_block)
        elif command == 'hash_data':
            self.hash_data(arguments[0], arguments[1])
        elif command == 'sign_data':
            self.sign_data(arguments[0], arguments[1], arguments[2])
        elif command == 'verify_data':
            self.verify_data(arguments[0], arguments[1], arguments[2])
        elif command == 'encrypt_data':
            self.encrypt_data(arguments[0], arguments[1], arguments[2])
        elif command == 'decrypt_data':
            self.decrypt_data(arguments[0], arguments[1], arguments[2])
        elif command == 'loop':
            self.loop(arguments[0], arguments[1], arguments[2])
        elif command == 'define_func':
            self.define_function(arguments[0], arguments[1:])
        elif command == 'call_func':
            self.call_function(arguments[0], arguments[1:])
        elif command == 'define_var':
            self.define_variable(arguments[0], arguments[1])
        # Add more commands as needed

    def execute_code(self, script_code):
        lines = script_code.split('\n')
        for line in lines:
            self.execute_line(line)

    def hash_data(self, algorithm, data):
        if algorithm == 'sha256':
            hasher = hashlib.sha256(data.encode())
        elif algorithm == 'sha1':
            hasher = hashlib.sha1(data.encode())
        elif algorithm == 'md5':
            hasher = hashlib.md5(data.encode())
        elif algorithm == 'sha512':
            hasher = hashlib.sha512(data.encode())
        elif algorithm == 'ripemd160':
            hasher = RIPEMD160.new(data.encode())
        else:
            print(f"Hashing algorithm {algorithm} is not supported")
            return
        print(hasher.hexdigest())

    def sign_data(self, algorithm, private_key_file, data):
        if algorithm == 'rsa':
            with open(private_key_file, 'r') as key_file:
                private_key = RSA.import_key(key_file.read())
            hash_obj = SHA256.new(data.encode())
            signature = pkcs1_15.new(private_key).sign(hash_obj)
            print(base64.b64encode(signature).decode())

    def verify_data(self, algorithm, public_key_file, signature, data):
        if algorithm == 'rsa':
            with open(public_key_file, 'r') as key_file:
                public_key = RSA.import_key(key_file.read())
            hash_obj = SHA256.new(data.encode())
            try:
                pkcs1_15.new(public_key).verify(hash_obj, base64.b64decode(signature))
                print("Signature is valid")
            except (ValueError, TypeError):
                print("Signature is invalid")

    def encrypt_data(self, algorithm, key_file, data):
        if algorithm == 'aes':
            with open(key_file, 'rb') as key_file:
                key = key_file.read()
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data.encode())
            print(base64.b64encode(cipher.nonce + tag + ciphertext).decode())
        elif algorithm == 'rsa':
            with open(key_file, 'r') as key_file:
                public_key = RSA.import_key(key_file.read())
            cipher = PKCS1_OAEP.new(public_key)
            ciphertext = cipher.encrypt(data.encode())
            print(base64.b64encode(ciphertext).decode())

    def decrypt_data(self, algorithm, key_file, ciphertext):
        if algorithm == 'aes':
            with open(key_file, 'rb') as key_file:
                key = key_file.read()
            raw = base64.b64decode(ciphertext)
            nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            print(data.decode())
        elif algorithm == 'rsa':
            with open(key_file, 'r') as key_file:
                private_key = RSA.import_key(key_file.read())
            cipher = PKCS1_OAEP.new(private_key)
            data = cipher.decrypt(base64.b64decode(ciphertext))
            print(data.decode())

    def loop(self, condition, true_block, false_block=None):
        while eval(condition):
            self.execute_block(true_block)
            if false_block:
                self.execute_block(false_block)

    def define_function(self, func_name, func_block):
        self.native_functions[func_name] = func_block

    def call_function(self, func_name, arguments):
        if func_name in self.native_functions:
            func_block = self.native_functions[func_name]
            for line in func_block:
                self.execute_line(line)

    def define_variable(self, var_name, value):
        self.env_variables[var_name] = value
        print(f"Variable {var_name} defined as {value}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: hydrax <file.hy>")
        sys.exit(1)

    file_path = sys.argv[1]
    script_runner = ObsidianScript()
    script_runner.run_script(file_path)
