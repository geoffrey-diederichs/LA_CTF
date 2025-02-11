from pwn import *
from ctypes import CDLL

def calc_rands(length:int, iterations:int, libc) -> list:
    rands = []
    for _ in range(length*iterations):
        rands.append(libc.rand())
    return rands

def shuffle_back(message:list, rands: list, libc) -> str:
    i = 0
    for r in reversed(rands):
        r = r % (i+1)
        message[i], message[r] = message[r], message[i]
        if (i == len(message)-1):
            i = 0
        else:
            i += 1
    return message

if __name__ == "__main__":
    p = remote("chall.lac.tf", 31313)

    libc = CDLL("/usr/lib64/libc.so.6")
    curr_time = libc.time(None)
    libc.srand(curr_time)
    
    message = p.recv()
    message = message.split(b"\n")[0]
    message = list(message.decode())

    rands = calc_rands(len(message), 22, libc)
    message = shuffle_back(message, rands, libc)

    print("".join(message))
