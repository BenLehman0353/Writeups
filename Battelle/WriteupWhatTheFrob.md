Challenge Name: WhatTheFrob

Category: Reverse Engineering / Binary Exploitation

Date: 

Author: Ben Lehman

This is my writeup for the WhatTheFrob ctf.
https://www.battelle.org/the-challenge/what-the-frob

I started with making an objdump
```
objdump -D wtfrob -M intel > wtfrob.dump.txt
```

I will be referencing this as well as Ghidra decompilations

I also got the strings from the file
```
strings -t x wtfrob > wtfrob.strings.txt
```

Here are some strings that look interesting that might be good to keep in mind:
```
   200a data.txt
   2016 encrypted.txt
   2028 My custom strfry implementation, because I didn't trust the randomess of the original..
   2080 wanna read a funny comment thread? https://sourceware.org/bugzilla/show_bug.cgi?id=4403
   20d8 Did you know Memfrob is a standard function?
   21a7 :*3$"
```

Now is a good time to give that thread a read. It is about a bug in the implementation of a joke function called strfry, which leads a user to mention a memfrob function that is apparently bad at encryption. 

This ctf did not come with instructions, but I think it is safe to say that I have to write something to decrypt encrypted.txt using the vulnerability in memfrob and also possibly strfry.

lets look at the decompile in Ghidra
```
undefined8 main(void)

{
  FILE *__dataStream;
  FILE *__encryptedStream;
  size_t dataLen;
  long lVar1;
  undefined8 *puVar2;
  long in_FS_OFFSET;
  byte bVar3;
  char data [16];
  undefined8 local_218 [65];
  long local_10;
  
  bVar3 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  srand(0x539);
  data[0] = '\0';
  data[1] = '\0';
  data[2] = '\0';
  data[3] = '\0';
  data[4] = '\0';
  data[5] = '\0';
  data[6] = '\0';
  data[7] = '\0';
  data[8] = '\0';
  data[9] = '\0';
  data[10] = '\0';
  data[0xb] = '\0';
  data[0xc] = '\0';
  data[0xd] = '\0';
  data[0xe] = '\0';
  data[0xf] = '\0';
  puVar2 = local_218;
  for (lVar1 = 0x3f; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + (ulong)bVar3 * -2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  __dataStream = fopen("data.txt","r");
  __encryptedStream = fopen("encrypted.txt","wb");
  fread(data,0x209,1,__dataStream);
  puts("My custom strfry implementation, because I didn\'t trust the randomess of the original.." );
  puts("wanna read a funny comment thread? https://sourceware.org/bugzilla/show_bug.cgi?id=4403" );
  strfry(data);
  puts("Did you know Memfrob is a standard function?");
  dataLen = strlen(data);
  memfrob(data,dataLen);
  fwrite(data,0x209,1,__encryptedStream);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
This program shuffles the data with its own implementation of strfry and then runs the result through memfrob.
The result is written to encrypted.txt.

In order to decrypt encrypted.txt I will have to reverse memfrob and then reverse strfry. Lets take a look at the documentation for memfrob.

https://man7.org/linux/man-pages/man3/memfrob.3.html
```
       The memfrob() function obfuscates the first n bytes of the memory
       area s by exclusive-ORing each character with the number 42.  The
       effect can be reversed by using memfrob() on the obfuscated memory
       area.

       Note that this function is not a proper encryption routine as the
       XOR constant is fixed, and is suitable only for hiding strings.
```

So all that has to be done is call memfrob on the data agan. That sounds easy enough.
memfrob XORs with 42. I can write my own version of it

Here is the basic C probram to decrypt (but not unshuffle) encrypted.txt:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *memfrob(void *s, size_t n) {
    unsigned char *p = s;
    while (n--) {
        *p ^= 0x2A;
        p++;
    }
    return s;
}

int main(void) {
    FILE *inFile = fopen("encrypted.txt", "rb");

    fseek(inFile, 0, SEEK_END);
    long fileSize = ftell(inFile);
    rewind(inFile);

    char *buffer = malloc(fileSize);

    if (fread(buffer, 1, fileSize, inFile) != fileSize) {
        perror("Failed to read the entire file");
        free(buffer);
        fclose(inFile);
        return 1;
    }
    fclose(inFile);

    memfrob(buffer, fileSize);

    FILE *outFile = fopen("decrypted.txt", "wb");

    fwrite(buffer, 1, fileSize, outFile);

    fclose(outFile);
    free(buffer);
    return 0;
}
```

Upon running it, I did not get at all what I expected.

```
---+-++.++++++--++++--++-+--+-++<+--+++++++++.+-++-+-.+++++-+++++-+++++--+.-++--+-++++-.-++.++++++.++-+++++++.+++-+++.+-<+.+++++-++++-+++.-+++---++-++.++++++++-+++.--+.+-++-+.+--++.+-++-+++.++--+++++++-+>--.+++++--+--.-+>-+-++-+++++++--+++-++-++++.+++<--+>-++-++-+-++-+++++++-.++>++-++-+++-++++-+++-++-+>+--+++-++++--++++++-+-++-+----.+-+-+<+.+-+++-.++++-+++++++++++++---++-++++++-+-+.+++.+-++.+++--+++++++++++++++++-+-+--.++++++++-+--+-++++++<-++++.+--++..>+++++++-++++++++.++.++++-+<++-++++-++--++-+---+++-++-+++-+++-++
```

This is a long string of the following characters:
```
+-.<>
```

I had no idea where to go from here, so I consulted chatGPT to find out what these characters could mean, and apparently it is from a programming language with a name that I can't say in polite company. Perhaps if I can un-stirfry this code and run it, I will have the flag.

Looking back at the decompiled main, it looks like it has a static seed it uses for the random number generator. If I can run the program on an ordered set of data of the same length, and then unfrob it, I can see exactly how it shuffles the data before encrypting it, and then knowing this I can unshuffle the code and run it.

That code has 521 characters. I will have to map how it shuffles 521 characters with the seed srand(0x539), and then reverse that map, and apply it to the shuffled code. First, lets grab the decompiled stir fry code:

```
char * strfry(char *__string)

{
  int j;
  size_t len;
  ulong i;
  char c;
  
  len = strlen(__string);
  if (len != 0) {
    for (i = 0; i < len - 1; i = i + 1) {
      j = rand();
      j = (int)i + (int)((ulong)(long)j % (len - i));
      c = __string[i];
      __string[i] = __string[j];
      __string[j] = c;
    }
  }
  return __string;
}
```

This C program I will write is going to be a little complicated. So I will add comments with each of the steps. 
```
#include <stdio.h>
#include <stdlib.h>

#define SIZE 521

int main(void){
    int indices[SIZE];
    int inverse[SIZE];

    // This array will be getting shuffled.
    for (int i = 0; i < SIZE; i++){
        indices[i] = i;
    }

    // This is the seed that was found in the decompiled code
    srand(0x539);

    // Pretty much just the decompiled stirfry. I removed the typecasts and initialized the values
    for (int i = 0; i < SIZE - 1; i = i + 1) {
        int j = rand();
        j = i + j % (SIZE - i);
        int c = indices[i];
        indices[i] = indices[j];
        indices[j] = c;
    }
    // indices[n] = the final location of the item that was originally at n

    // with this, and inverse of that relationship can be created
    for (int i = 0; i < SIZE; i = i + 1) {
        inverse[indices[i]] = i;
    }
    // inverse[finalPosition] = originalposition
    // with this, unshuffling is simple

    FILE *in = fopen("decrypted.txt", "rb");
    FILE *out = fopen("unshuffledAndDecrypted.txt", "wb");

    char shuffledData[SIZE];
    fread(shuffledData, 1, SIZE, in);

    char data[SIZE];
    for (int i = 0; i < SIZE; i++){
        data[i] = shuffledData[inverse[i]];
    }

    fwrite(data, SIZE, 1, out);
    
    fclose(in);
    fclose(out);

    return 0;
}
```

Now I have the resulting code in unshuffledAndDecrypted.txt
```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.++++++.-----------.++++++.++++++++++++++++++++.------------------.>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++.<++++++++++++++.----------------------.++++++++++++++++++.>.<---.---------------.++++++++.-----.>.<++++++++++++++++.-----.>.<--.------------.++++++++++.------.>.<+++++++++++++++.------------.+.++++++++++.>.<-----------------.++++++++++++++++++.+++.++++++.
```
This can be run in an interpreter like this one:https://copy.sh/brainfuck/

I verified that the unshuffled code printed a valid-looking flag, which I won’t include here to avoid spoilers.
