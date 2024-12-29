# QSafe-Lattice
This repository contains code and results for benchmarking the performance of RSA and Lattice-based cryptography algorithms. The focus is on evaluating their performance against potential quantum threats.

## Post-Quantum Cryptography Benchmarking

This repository contains code and results for benchmarking the performance of RSA and Lattice-based cryptography algorithms. The primary goal is to evaluate the performance trade-offs between these two families of cryptographic algorithms, with a focus on their suitability in a post-quantum world.

## Implemented Algorithms:
RSA:

Key Generation (RSA-2048, RSA-4096), Encryption (RSA-OAEP), Decryption

Lattice-based:

Kyber: Key Generation, Encapsulation, Decapsulation (Kyber512, Kyber768, Kyber1024)

## Performance Metrics:
Key Generation Time: Time taken to generate public and private keys.

Encryption/Encapsulation Time: Time required to encrypt/encapsulate a message.

Decryption/Decapsulation Time: Time required to decrypt/decapsulate a message.

Memory Usage: Peak memory consumption during key generation, encryption/encapsulation, and decryption/decapsulation.

Ciphertext Size: Size of the ciphertext compared to the plaintext size.

## Methodology:
Implementation: Implementations are written in Python with libraries like PyCryptodome for consistent benchmarking.

Testing: Performance is measured on a standard desktop machine with an Intel i7 processor and 16GB RAM.

Data Collection: Each test is repeated multiple times, and the average performance is recorded.

## Results:
Performance Tables: Results are presented in tables summarizing key generation, encryption/encapsulation, and decryption/decapsulation times for different key sizes and parameter sets.

Graphs: Visualizations (line graphs, bar charts) are used to illustrate performance trends, compare algorithms, and analyze the impact of key sizes and other parameters.

## Discussion:
Performance Comparison: Analyze the performance trade-offs between RSA and Lattice-based cryptography.

Quantum Threat Mitigation: Discuss the implications of quantum computing on the security of RSA and the advantages of Lattice-based cryptography in a post-quantum world.

Limitations: Acknowledge the limitations of this benchmarking study, such as the specific hardware and software environment used, the limited number of algorithms tested, and the potential for optimization opportunities.

## Future Work:
Implement and benchmark other post-quantum algorithms.
Explore the impact of different hardware and software platforms.
Investigate the security implications of side-channel attacks.
Conduct more in-depth analysis of resource consumption and energy efficiency.
