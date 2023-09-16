# urlpath [![GoDoc Badge][badge]][godoc] [![CI Badge][ci-badge]][ci-url]

`urlpath` is a Golang library for matching paths against a template, or
constructing paths using a template. It's meant for applications that take in
REST-like URL paths, and need to validate and extract data from those paths.

[badge]: https://godoc.org/github.com/ucarion/urlpath?status.svg
[godoc]: https://godoc.org/github.com/ucarion/urlpath
[ci-badge]: https://github.com/ucarion/urlpath/workflows/.github/workflows/test.yml/badge.svg
[ci-url]: https://github.com/ucarion/urlpath/actions

This is easiest explained with an example:

```go
import "github.com/ucarion/urlpath"

var getBookPath = urlpath.New("/shelves/:shelf/books/:book")

func main() {
  inputPath := "/shelves/foo/books/bar"
  match, ok := getBookPath.Match(inputPath)
  if !ok {
    // handle the input not being valid
    return
  }

  // Output:
  //
  // foo
  // bar
  fmt.Println(match.Params["shelf"])
  fmt.Println(match.Params["book"])
}
```

One slightly fancier feature is support for trailing segments, like if you have
a path that ends with a filename. For example, a GitHub-like API might need to
deal with paths like:

```text
/ucarion/urlpath/blob/master/src/foo/bar/baz.go
```

You can do this with a path that ends with "*". This works like:

```go
path := urlpath.New("/:user/:repo/blob/:branch/*")

match, ok := path.Match("/ucarion/urlpath/blob/master/src/foo/bar/baz.go")
fmt.Println(match.Params["user"])   // ucarion
fmt.Println(match.Params["repo"])   // urlpath
fmt.Println(match.Params["branch"]) // master
fmt.Println(match.Trailing)         // src/foo/bar/baz.go
```

Additionally, you can call `Build` to construct a path from a template:

```go
path := urlpath.New("/:user/:repo/blob/:branch/*")

res, ok := path.Build(urlpath.Match{
  Params: map[string]string{
    "user": "ucarion",
    "repo": "urlpath",
    "branch": "master",
  },
  Trailing: "src/foo/bar/baz.go",
})

fmt.Println(res) // /ucarion/urlpath/blob/master/src/foo/bar/baz.go
```

## How it works

`urlpath` operates on the basis of "segments", which is basically the result of
splitting a path by slashes. When you call `urlpath.New`, each of the segments
in the input is treated as either:

* A parameterized segment, like `:user`. All segments starting with `:` are
  considered parameterized. Any corresponding segment in the input (even the
  empty string!) will be satisfactory, and will be sent to `Params` in the
  outputted `Match`. For example, data corresponding to `:user` would go in
  `Params["user"]`.
* An exact-match segment, like `users`. Only segments exactly equal to `users`
  will be satisfactory.
* A "trailing" segment, `*`. This is only treated specially when it's the last
  segment -- otherwise, it's just a usual exact-match segment. Any leftover data
  in the input, after all previous segments were satisfied, goes into `Trailing`
  in the outputted `Match`.

## Performance

Although performance wasn't the top priority for this library, `urlpath` does
typically perform better than an equivalent regular expression. In other words,
this:

```go
path := urlpath.New("/test/:foo/bar/:baz")
matches := path.Match(...)
```

Will usually perform better than this:

```go
r := regexp.MustCompile("/test/(?P<foo>[^/]+)/bar/(?P<baz>[^/]+)")
matches := r.FindStringSubmatch(...)
```

The results of `go test -benchmem -bench .`:

```text
goos: darwin
goarch: amd64
pkg: github.com/ucarion/urlpath
BenchmarkMatch/without_trailing_segments/urlpath-8 	 1436247	       819 ns/op	     784 B/op	      10 allocs/op
BenchmarkMatch/without_trailing_segments/regex-8   	  693924	      1816 ns/op	     338 B/op	      10 allocs/op
BenchmarkMatch/with_trailing_segments/urlpath-8    	 1454750	       818 ns/op	     784 B/op	      10 allocs/op
BenchmarkMatch/with_trailing_segments/regex-8      	  592644	      2365 ns/op	     225 B/op	       8 allocs/op
```

Do your own benchmarking if performance matters a lot to you. See
`BenchmarkMatch` in `urlpath_test.go` for the code that gives these results.
