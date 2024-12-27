#! /usr/bin/python3

a = "2F 68 6F 6D 65 2F 73 68 65 6C 6C 5F 62 61 73 69 63 2F 66 6C 61 67 5F 6E 61 6D 65 5F 69 73 5F 6C 6F 6F 6F 6F 6F 6F 6E 67"

a = a.split(" ")
a.reverse() 
b = '0x'
c = 0
for i in a : 
    if c == 7 :
        print(b)
        b = '0x'
        c = 0
    b += str(i)
    c += 1

