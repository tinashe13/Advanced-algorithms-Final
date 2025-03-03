# SHA-256 Implementation in C++

This repository contains a straightforward C++ implementation of the [SHA-256](https://en.wikipedia.org/wiki/SHA-2) cryptographic hash function. The code reads data from a file named `test.txt`, processes it in 512-bit chunks, and then outputs the calculated SHA-256 hash in hexadecimal form.

---

## Table of Contents

1. [Overview of SHA-256](#overview-of-sha-256)  
2. [How the Code Works](#how-the-code-works)  
3. [File Structure](#file-structure)  
4. [Build Instructions](#build-instructions)  
5. [Usage](#usage)  
6. [Example](#example)  
7. [License](#license)  

---

## Overview of SHA-256

**SHA-256** is a cryptographic hash function from the SHA-2 family designed by the National Institute of Standards and Technology (NIST). It produces a 256-bit (32-byte) hash value, often represented as a 64-character hexadecimal string. 

Key properties of SHA-256 include:
- **Determinism**: The same input always produces the same hash.
- **One-way function**: Infeasible to reconstruct the original input from the hash alone.
- **Collision resistance**: Extremely unlikely for two different inputs to produce the same hash value.

---

## How the Code Works

1. **Reading the Input File**  
   The program opens `test.txt` in binary mode and reads it in 4 KB chunks. Each chunk is then passed to the `SHA256` class for incremental hashing.

2. **SHA-256 Class**  
   - Maintains an internal state (`hashValues`), a **message length** counter (in bits), and a buffer (`messageBlock`) to accumulate 64 bytes (512 bits) at a time.
   - Whenever the buffer reaches 64 bytes, the code processes it using the `processBlock()` function, which implements the SHA-256 compression step.
   - After all input is processed, a **finalization** step pads the remaining data, appends the message length, and processes this final block.

3. **Compression Function** (`processBlock()`)  
   - Expands the 64-byte block into 64 32-bit words (the “message schedule”).
   - Uses **bitwise operations** (`rotateRight`, `choose`, `majority`) and **constants** (`ROUND_CONSTANTS`) following the official SHA-256 specification.
   - Runs a main loop of 64 rounds, updating the intermediate hash state.

4. **Output**  
   - After finalization, `hashValues` (the 8 final 32-bit words) are converted into a 64-digit hexadecimal string.

---

## File Structure

