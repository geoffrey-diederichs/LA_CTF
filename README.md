# the-eye

```
rev/the-eye

Author : aplet123

I believe we’ve reached the end of our journey. All that remains is to collapse the innumerable possibilities before us.

nc chall.lac.tf 31313
```

We were given a [Dockerfile](/Dockerfile) and an [executable](/the-eye) :

```console
$ ./the-eye 
msg.txt is missing

$ echo "1234" > msg.txt && ./the-eye 
3421
```

The program needs a `msg.txt` file to execute, and shuffles it's content before printing it out. Let's try connecting to the server :

```console
$ nc chall.lac.tf 31313
rheehtrt  i thna e  itri2neldueptbeoit_hl y tEr,taresnn  -g eiiilsulia comteeaat,cg o t Trsgnate_aaau;e}mt2Eussi hn   p  gr astdaseffrghahortoextys. u s  loaaaHitticedomiistet,hngspti ierrstcaysyctt aseitssmtou seolier tdte r, nyenw tsnyti ep fsi a al   ocei acnrendprhWhnit aasi naen seipehenar   tliestsodt y  n   hw ae a sett tntreroeauiiympdsgde_uoai{htoenc ndnlee cd.  aagttnr tstidsa,lehlap axloNdrle lna neegmsup rsoleee ootgyc sdnre npmganieav  oolsee,nOtlealout xahhvbe ee igrt peh,e tfrrnencaidi foeensyhvudm ess_sm  esgmhann exacosda essecfute n_eowelehtarohm ce  cntsr-hyleehgpsepeacyt_ ulnsea m dmshaedH ldeofdaye eo.cxslA hun  vtensel aeia ena  .vseelo nwhrohtdervc aednsi odpameseemhtn_og hne op?pi  rr  ttfirWd r
```

It seems like in order to solve this challenge we'll need to get the original message, which will probably include the flag. Let's try and reverse it using Ghidra.

## Static Analysis

```C
undefined8 main(void)
{
  time_t curr_time;
  char *message;
  undefined4 i;
  
  curr_time = time((time_t *)0x0);
  srand((uint)curr_time);
  message = (char *)read_msg();
  for (i = 0; i < 22; i = i + 1) {
    shuffle(message);
  }
  puts(message);
  free(message);
  return 0;
}
```

The `main()` function is using the current time as a seed for the `rand` function : `srand((uint)curr_time);`.

It is then getting the content of the `msg.txt` file using the `read_msg()` function, before calling in a loop 22 times `shuffle()` :

```C
void shuffle(char *message)
{
  int random;
  size_t len;
  int i;
  char curr_char;
  int length;
  
  len = strlen(message);
  length = (int)len;
  while (i = length + -1, -1 < i) {
    random = rand();
    curr_char = message[i];
    message[i] = message[random % length];
    message[random % length] = curr_char;
    length = i;
  }
  return;
}
```

`shuffle()` swaps the last byte from `message` with another random one determined using `rand()`. It's repeating this operation on every byte of the `message`, from the last byte to the first one.

Once this encoding done 22 times as mentionned earlier, the `main` function prints out the encoded `message` : `puts(message);`.

Since the whole operation is using a pseudo-random generator with a known seed, we could replicate this randomness, and decode the message by inverting this algorithm.

## Scripting

First things first, let's break the randomness :

```python3
from ctypes import CDLL

if __name__ == "__main__":
    libc = CDLL("/usr/lib64/libc.so.6")
    curr_time = libc.time(None)
    libc.srand(curr_time)
```

Using `CDLL` to import a `libc` we can execute C functions from a Python script. This way we can execute the same functions as the program and get the same outputs. We can also dynamically check whether this is working using GDB.

First let's get the output of `time()` :

```gdb
───────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555370 <main+0004>      sub    rsp, 0x10
   0x555555555374 <main+0008>      mov    edi, 0x0
●  0x555555555379 <main+000d>      call   0x5555555550a0 <time@plt>
 → 0x55555555537e <main+0012>      mov    edi, eax
   0x555555555380 <main+0014>      call   0x555555555080 <srand@plt>
   0x555555555385 <main+0019>      mov    eax, 0x0
   0x55555555538a <main+001e>      call   0x5555555551f9 <read_msg>
   0x55555555538f <main+0023>      mov    QWORD PTR [rbp-0x10], rax
   0x555555555393 <main+0027>      mov    DWORD PTR [rbp-0x4], 0x0

```

```gdb
gef➤  p $rax
$1 = 0x67ab9472
```

Now the output of the first `rand()` :

```gdb
───────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555303 <shuffle+0021>   mov    DWORD PTR [rbp-0x4], eax
   0x555555555306 <shuffle+0024>   jmp    0x555555555362 <shuffle+128>
●  0x555555555308 <shuffle+0026>   call   0x5555555550f0 <rand@plt>
 → 0x55555555530d <shuffle+002b>   mov    edx, DWORD PTR [rbp-0x4]
   0x555555555310 <shuffle+002e>   lea    ecx, [rdx+0x1]
   0x555555555313 <shuffle+0031>   cdq    
   0x555555555314 <shuffle+0032>   idiv   ecx
   0x555555555316 <shuffle+0034>   mov    DWORD PTR [rbp-0xc], edx
   0x555555555319 <shuffle+0037>   mov    eax, DWORD PTR [rbp-0x4]
```

```gdb
gef➤  p $rax
$2 = 0x6d692494
```

And of the second `rand()` :

```gdb
───────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555303 <shuffle+0021>   mov    DWORD PTR [rbp-0x4], eax
   0x555555555306 <shuffle+0024>   jmp    0x555555555362 <shuffle+128>
●  0x555555555308 <shuffle+0026>   call   0x5555555550f0 <rand@plt>
 → 0x55555555530d <shuffle+002b>   mov    edx, DWORD PTR [rbp-0x4]
   0x555555555310 <shuffle+002e>   lea    ecx, [rdx+0x1]
   0x555555555313 <shuffle+0031>   cdq    
   0x555555555314 <shuffle+0032>   idiv   ecx
   0x555555555316 <shuffle+0034>   mov    DWORD PTR [rbp-0xc], edx
   0x555555555319 <shuffle+0037>   mov    eax, DWORD PTR [rbp-0x4]
```

```gdb
gef➤  p $rax
$3 = 0x1a174d95
```

Let's see if we get the same outputs in Python with the same seed :

```python
from ctypes import CDLL

if __name__ == "__main__":
    libc = CDLL("/usr/lib64/libc.so.6")
    libc.srand(0x67ab9472)
    r1, r2 = libc.rand(), libc.rand()

    print(hex(r1), hex(r2))
```

```console
$ python3 solve.py
0x6d692494 0x1a174d95
```

This is working, we can predict the output of every `rand()`.

Now we need to invert `shuffle()` by swapping back every byte to their right place one by one starting with the last pair of bytes that was swapped. That's why we first need to determine the output of every `rand()` call. `rand()` being called once for every byte of `message` in `shuffle()` and `shuffle()` being called 22 times, `rand()` is called `len(message)*22` in total. Let's calculate every output of `rand()` : 

```python
from pwn import *
from ctypes import CDLL

def calc_rands(length:int, iterations:int, libc) -> list:
    rands = []
    for _ in range(length*iterations):
        rands.append(libc.rand())
    return rands

if __name__ == "__main__":
    p = process("./the-eye")

    libc = CDLL("/usr/lib64/libc.so.6")
    curr_time = libc.time(None)
    libc.srand(curr_time)
    
    message = p.recv()
    message = message.split(b"\n")[0]
    message = list(message.decode())

    rands = calc_rands(len(message), 22, libc)
    print(len(rands), rands[-1])
```

In this script I used `pwntools` to run `the-eye`, then used `CDLL` at the same time as the program to break it's randomness, then saved every `rand()` output used by the program in `rands` :

```console
$ echo "Testing this script" > msg.txt

$ python3 solve.py
[+] Starting local process './the-eye': pid 20734
[*] Process './the-eye' stopped with exit code 0 (pid 20734)
418 676159644
```

Now we only need to invert `shuffle()` using the generated `rands` :

```python
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
    p = process("./the-eye")

    libc = CDLL("/usr/lib64/libc.so.6")
    curr_time = libc.time(None)
    libc.srand(curr_time)
    
    message = p.recv()
    print(f"Received : {message}")
    message = message.split(b"\n")[0]
    message = list(message.decode())

    rands = calc_rands(len(message), 22, libc)
    message = shuffle_back(message, rands, libc)
    message = "".join(message)
    print(f"Decoded : {message}")
```

Which gives us :

```
$ echo "Testing this script" > msg.txt

$ python3 solve.py
[+] Starting local process './the-eye': pid 22050
[*] Process './the-eye' stopped with exit code 0 (pid 22050)
Received : b'tsTsn pticetshi igr\n'
Decoded : Testing this script
```

## Exploit

Using this [final script](/solve.py) to connect back to the servers and decode the message we get :

```console
$ python3 solve.py
[+] Opening connection to chall.lac.tf on port 31313: Done
Outer Wilds is an action-adventure video game set in a small planetary system in which the player character, an unnamed space explorer referred to as the Hatchling, explores and investigates its mysteries in a self-directed manner. Whenever the Hatchling dies, the game resets to the beginning; this happens regardless after 22 minutes of gameplay due to the sun going supernova. The player uses these repeated time loops to discover the secrets of the Nomai, an alien species that has left ruins scattered throughout the planetary system, including why the sun is exploding. A downloadable content expansion, Echoes of the Eye, adds additional locations and mysteries to the game. lactf{are_you_ready_to_learn_what_comes_next?}
[*] Closed connection to chall.lac.tf port 31313
```
