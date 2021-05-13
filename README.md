# Security Analysis of PASS Encrypt

This GitHub repository contains the Sage code in order to perform attacks against PASS Encrypt to estimate its concrete security. 

As explained in Section 7.3 (Security Analysis) of Chapter 7 (PASS Encrypt) of my thesis, the encryption scheme can be attacked in three different ways:
- Key Recovery Attack
- Randomness Recovery Attack
- Plaintext Recovery Using Hints Attack

In Table 7.1 of my thesis we provide security estimations for concrete parameters.
The link of the thesis will follow, once it has been published.

The following files of this repository provide the necessary material to verify those security claims.

The folder “framework” is directly copied from the Leaky LWE Estimator repository (https://github.com/lducas/leaky-LWE-Estimator).

The folder “attacks” contains one sage file which performs the attacks on the (slightly modified version of) PASS Encrypt, as presented in the thesis. PASS Encrypt was first described by Hoffstein and Silverman [HS15].
We refer to the descriptions within those files for further details on how to execute them.
Here a simple example to execture with Sage within the folder “attacks”:

#-- Example in Sage --#
- ..: load("pass_encrypt.sage")
- ..: d,t,q=256,128,7681
- ..: attack(d,t,q,"light")

We also included a pdf file (Experiments_Results.pdf) that summarizes all results mentioned in the thesis (Table 7.1 and Table 7.2).

Please make sure that your Sage version is up to date.
We tested it on version 8.8 (Release Date: 2019-06-26) using Python 3.7.7.

[HS15] Jeffrey Hoffstein, Joseph H. Silverman. PASS-Encrypt: a public key cryptosystem based on partial evaluation of polynomials. Des. Codes Cryptogr. 77(2-3): 541-552 (2015)
