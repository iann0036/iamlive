# About baseconv [![Build Status][t-badge]][t-link] [![Coverage][c-badge]][c-link]

`baseconv` is a simple [Go][go-project] package for converting between strings
in arbitrary bases.

`baseconv` is useful when working with extremely large numbers stored in a
string format and where there is a need to convert between different base
representations (ie, decimal, hex, octal, etc). For example, `baseconv` is
useful when converting from "url-safe" UUIDs to a decimal or binary
representation.

`baseconv` was originally written to solve a similar use-case as PHP's
[`base_convert`][base-convert] function.

## Installing

Install the package via the following:

    $ go get -u github.com/kenshaw/baseconv

## Using

`baseconv` can be used similarly to the following:

```go
// _example/example.go
package main

import (
	"fmt"

	"github.com/kenshaw/baseconv"
)

func main() {
	valHex := "70b1d707eac2edf4c6389f440c7294b51fff57bb"
	fmt.Println("hex string: " + valHex)
	valDec, _ := baseconv.DecodeHexToDec(valHex)
	val62, _ := baseconv.Convert(valHex, baseconv.DigitsHex, baseconv.Digits62)
	val36, _ := baseconv.Convert(val62, baseconv.Digits62, baseconv.Digits36)

	fmt.Println("dec string: " + valDec)
	fmt.Println("62 string:  " + val62)
	fmt.Println("36 string:  " + val36)

	conVal36, _ := baseconv.Decode36ToDec(val36)
	fmt.Printf("dec and 36 values same: %t\n", valDec == conVal36)
}
```

Output:

```sh
$ cd $GOPATH/src/github.com/kenshaw/baseconv/example/ && go run example.go
hex string: 70b1d707eac2edf4c6389f440c7294b51fff57bb
dec string: 643372930067913326838082478477533553256088688571
62 string:  g4WuOGCMWgcPa70d91BezVvvvaX
36 string:  d5wjfaew7fypqn2ka6xpofdlwns9ha3
dec and 36 values same: true
```

Please see [the GoDoc API page][godoc] for a full API listing.

[t-badge]: https://travis-ci.org/kenshaw/baseconv.svg
[t-link]: https://travis-ci.org/kenshaw/baseconv
[c-badge]: https://coveralls.io/repos/kenshaw/baseconv/badge.svg?branch=master&service=github
[c-link]: https://coveralls.io/github/kenshaw/baseconv?branch=master
[go-project]: http://www.golang.org/project/
[base-convert]: http://php.net/manual/en/function.base-convert.php
[godoc]: http://godoc.org/github.com/kenshaw/baseconv
