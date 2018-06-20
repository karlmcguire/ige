# ige
[![GoDoc](https://img.shields.io/badge/api-reference-blue.svg)](https://godoc.org/github.com/karlmcguire/ige)
[![Go Report Card](https://img.shields.io/badge/go%20report-A%2B-green.svg)](https://goreportcard.com/report/github.com/karlmcguire/ige)

IGE block cipher mode for Go.

## about

<p align="center">
    <img src="https://i.imgur.com/2xsO8VY.png" />
</p>

## testing
I'm using the test vectors described in the [official OpenSSL IGE paper](https://www.links.org/files/openssl-ige.pdf).

You can execute the tests yourself by running:

```
$ go test
```

### test vector 1

#### key

```
00010203 04050607 08090A0B 0C0D0E0F
```

#### initialization vector

```
00010203 04050607 08090A0B 0C0D0E0F
10111213 14151617 18191A1B 1C1D1E1F
```

#### plaintext

```
00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000
```

#### ciphertext

```
1A8519A6 557BE652 E9DA8E43 DA4EF445
3CF456B4 CA488AA3 83C79C98 B34797CB
```

### test vector 2

#### key

```
54686973 20697320 616E2069 6D706C65
```

#### initialization vector

```
6D656E74 6174696F 6E206F66 20494745
206D6F64 6520666F 72204F70 656E5353
```

#### plaintext

```
99706487 A1CDE613 BC6DE0B6 F24B1C7A
A448C8B9 C3403E34 67A8CAD8 9340F53B
```

#### ciphertext

```
4C2E204C 65742773 20686F70 65204265
6E20676F 74206974 20726967 6874210A
```
