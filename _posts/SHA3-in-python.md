---
layout: post
title:  "SHA3 in python"
image: 'https://miro.medium.com/max/875/1*7swEc1wqlnkNHQpd8Wgwwg.png'
date:   2020-07-24 00:05:27
tags:
- sha3
- Python3
- Hash Functions
- Keccak
- Cryptography
description: ''Python 3 code for SHA-3 cryptographic algorithm '
categories:
- Cryptography
---

# SHA-3-Python
Python 3 code for SHA-3 cryptographic algorithm
This code has clean and easy to understand the implementation of SHA-3 Cryptographic Algorithm.Comments are done to make it easier to understand for someone who is new to SHA-3 and python.SHA-3 falls under sponge functions while sha-0,sha-1,sha-2 and MD-5 hash functions fall under Merkle Damgard construction.

Note:It's still under progress

![SHA-3 High Level Overview](https://github.com/TheLeopardsH/SHA3-Python-3-/blob/master/SHA3.png)

There are four levels of security in SHA-3 as follows

| Type        |  Output Length   |  Rate (r)     |    Capacity (c)   |
| ----------- |  --------------- | ------------- |  ---------------  | 
| SHA3-224    |       224        |    1152       |       448         |
| SHA3-256    |       256        |    1088       |       512         |
| SHA3-384    |       384        |     832       |       768         |
| SHA3-512    |       512        |     576       |      1024         |

Stage 1:
       Stage 1 is Padding stage
       
Stage 2:
       Stage 2 is State size
 
Stage 3:
       Stage 3 is Aborbing phase
       
Stage 4:
       Stage 4 is Squeezing phase

## Padding:
The input M to the hash algorithm SHA-3 is padded with 10∗1, i.e. two 1’s and as many 0’s in between (possibly none) until the padded length is a multiple of 1088 (= 1600−512)(Rate r Changes with SHA-3 type i.e SHA-256). You must append at least two 1’s, with as many 0’s in between (possibly none) so that the padded length is a multiple of 1088.


# The F-Function Of SHA-3
The f-Function of SHA-3 Consists of 5 sub-Functions which are theta,rho,pi,chi and iota.
In order to understand these 5 sub_functions,we divide the input 1600 bits state into 5x5 matrix and each one of the matrix has 64 bits(64 bit register=1 word) making it 5x5x64.

## Theta:
        Each of 1600 state bits are replaced by the XOR sum of 11 bits:
        (The original bit) XOR (5 bit column "to the left" of the bit) XOR  (5 bit column "to the right"  and one position "to the front" of the bit).
## rho:
     Each word is rotated by a fixed number of position by a fixed table.
     
## pi:
     We Permutate the 64 bit words locations in 5x5 matrix.
  
 
##  chi:
       
      A_out [i][j][k] = A[i][j][k] XOR ( (A[i + 1][j][k] XOR 1) AND (ain[i + 2][j][k]) )
    
## iota:
      Add constants  to word (0,0)
      
      
 ```python
 
#python3 code for sha3 cryptographic algorithm
import numpy as np
import random
l = 6  # value of l = {0, 1, 2, 3, 4, 5, 6}
b = 25*(2**l)  # b = state size (value of b = {25, 50, 100, 200, 400, 800, 1600} )
# For SHA-3 the value of ‘l’ was 6 and the
# so rounds turn out to be
rounds = 12 + 2*l  # 24 rounds
print(rounds+' Rounds in SHA-3')
# So SHA-3 has state size of 1600 bits and the number of rounds of computations will be 24


# 1600 bits(1 dimensional array) to 3 dimensional array of 5x5x64
def _1Dto3D(A):
    A_out = np.zeros((5, 5, 64), dtype = int) # Initialize empty 5x5x64 array
    for i in range(5):
        for j in range(5):
            for k in range(64):
                A_out[i][j][k] = A[64*(5*j + i) + k]
    return A_out


def theta(A):
        A_out = np.zeros((5,5,64), dtype = int)  # Initialize empty 5x5x64 array
       #A_out = [[[0 for _ in range(64)] for _ in range(5)] for _ in range(5)] #without numpy
        for i in range(5):
                for j in range(5):
                        for k in range(64):
                            C=sum([A[(i-1)%5][ji][k] for ji in range(5)]) % 2 # XOR=mod2 5 bit column "to the left" of the original bit
                            D=sum([A[((i+1) % 5)][ji][(k-1)%64] for ji in range(5)]) % 2 #XOR=mod2 5 bit column "to the right"  and one position "to the front" of the original bit
                            temp=C+D+A[i][j][k] % 2 #XORing original bit with A and B
                            A_out[i][j][k]=temp
        return A_out

#Rho : Each word is rotated by a fixed number of position according to table.
def rho(A):
    rhomatrix=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
    rhom = np.array(rhomatrix, dtype=int)  # Initialize empty 5x5x64 array
    A_out = np.zeros((5,5,64), dtype = int)
    for i in range(5):
        for j in range(5):
            for k in range(64):
                A_out[i][j][k] = A[i][j][k - rhom[i][j]] #  A[i][j][k − (t + 1)(t + 2)/2] so here rhom[i][j] Use lookup table to "calculate" (t + 1)(t + 2)/2
    return A_out

#Pi: Permutate the 64 bit words
def pi(A):
    A_out = np.zeros((5,5,64), dtype = int) # Initialize empty 5x5x64 array
    for i in range(5):
        for j in range(5):
            for k in range(64):
                A_out[j][(2*i+3*j)%5][k] = A[i][j][k]
    return A_out

# A_out [i][j][k] = A[i][j][k] XOR ( (A[i + 1][j][k] XOR 1) AND (ain[i + 2][j][k]) )
def chi(A):
    A_out = np.zeros((5,5,64), dtype = int) # Initialize empty 5x5x64 array
    for i in range(5):
        for j in range(5):
            for k in range(64):
                A_out = (A[i][j][k]+(((A[(i + 1)%5][j][k] + 1 )% 2) * (A[(i + 2)%5][j][k]))) % 2
    return A_out

#iota: add constants  to word (0,0)
# aout[i][j][k] = ain[i][j][k] ⊕ bit[i][j][k]
# for 0 ≤ ℓ ≤ 6, we have bit[0][0][2ℓ − 1] = rc[ℓ + 7ir]
def iota(A, round):
    # Initialize empty arrays
    A_out = A.copy()
    bit = np.zeros((5,5,64), dtype=int)
    rc = np.zeros((168), dtype=int)

    #generation of rc as Linear Feedback Shift Register
    w = np.array([1,0,0,0,0,0,0,0], dtype = int)
    rc[0] = w[0]
    for i in range(1, 168): #7*24
        w = [w[1],w[2],w[3],w[4],w[5],w[6],w[7], (w[0]+w[4]+w[5]+w[6]) % 2]
        rc[i] = w[0]

    # Calculate A_out
    for l in range(7):
        A_out[0][0][2**l - 1] ^=rc[l + 7*round])

# 5x5x64 (three-dimensional array) into 1600 bits(one-dimensional array)
def _3Dto1D(A):
    A_out = np.zeros(1600, dtype = int) # Initialize empty array of size 1600
    for i in range(5):
        for j in range(5):
            for k in range(64):
                A_out[64*(5*j+i)+k] = A[i][j][k]
    return A_out

# 24 X (ι ◦ χ ◦ π ◦ ρ ◦ θ)
def SHA3(SHA_in):
    length=len(SHA_in)
    A_3D = _1Dto3D(SHA_in)
    for r in range(24):
        SHA_out_3D = iota(chi(pi(rho(theta(A_3D)))), r)
    SHA_out = _3Dto1D(SHA_out_3D)
    return SHA_out
 
 
 ```
      
