// Package urlpath matches paths against a template. It's meant for applications
// that take in REST-like URL paths, and need to validate and extract data from
// those paths.
//
// See New for documentation of the syntax for creating paths. See Match for how
// to validate and parse an inputted path.
package urlpath

import "strings"

// Path is a representation of a sequence of segments.
//
// To construct instances of Path, see New.
type Path struct {
	// A sequence of constraints on what valid segments must look like.
	Segments []Segment

	// Whether additional, trailing segments after Segments are acceptable.
	Trailing bool
}

// Segment is a constraint on a single segment in a path.
type Segment struct {
	// Whether this segment is parameterized.
	IsParam bool

	// The name of the parameter this segment will be mapped to.
	Param string

	// The constant value the segment is expected to take.
	Const string
}

// Match represents the data extracted by matching an input against a Path.
//
// To construct instances of Match, see the Match method on Path.
type Match struct {
	// The segments in the input corresponding to parameterized segments in Path.
	Params map[string]string

	// The trailing segments from the input. Note that the leading slash from the
	// trailing segments is not included, since it's implied.
	//
	// An exception to this leading slash rule is made if the Path was constructed
	// as New("*"), in which case Trailing will be identical to the inputted
	// string.
	Trailing string
}

// New constructs a new Path from its human-readable string representation.
//
// The syntax for paths looks something like the following:
//
//  /shelves/:shelf/books/:book
//
// This would match inputs like:
//
//  /shelves/foo/books/bar
//  /shelves/123/books/456
//  /shelves/123/books/
//  /shelves//books/456
//  /shelves//books/
//
// But not any of the following:
//
//  /shelves/foo/books
//  /shelves/foo/books/bar/
//  /shelves/foo/books/bar/pages/baz
//  /SHELVES/foo/books/bar
//  shelves/foo/books/bar
//
// Optionally, a path can allow for "trailing" segments in the input. This is
// done using a segment simply named "*". For example, this path:
//
//  /users/:user/files/*
//
// Would match inputs like:
//
//  /users/foo/files/
//  /users/foo/files/foo/bar/baz.txt
//  /users/foo/files////
//
// But not:
//
//  /users/foo
//  /users/foo/files
//
// The asterisk syntax for trailing segments only takes effect on the last
// segment. If an asterisk appears in any other segment, it carries no special
// meaning.
//
// In more formal terms, the string representation of a path is a sequence of
// segments separated by slashes. Segments starting with colon (":") are treated
// as "parameter" segments (see Match).
//
// If the final segment is just the character asterisk ("*"), it is treated as
// an indication that the path accepts trailing segments, and not included in
// the Segments of the return value. Instead, Trailing in the return value is
// marked as true.
func New(path string) Path {
	inSegments := strings.Split(path, "/")
	trailing := inSegments[len(inSegments)-1] == "*"

	var outSegments []Segment
	if trailing {
		outSegments = make([]Segment, len(inSegments)-1)
	} else {
		outSegments = make([]Segment, len(inSegments))
	}

	for i := 0; i < len(outSegments); i++ {
		if strings.HasPrefix(inSegments[i], ":") {
			outSegments[i] = Segment{IsParam: true, Param: inSegments[i][1:]}
		} else {
			outSegments[i] = Segment{IsParam: false, Const: inSegments[i]}
		}
	}

	return Path{Segments: outSegments, Trailing: trailing}
}

// Match checks if the input string satisfies a Path's constraints, and returns
// parameter and trailing segment information.
//
// The second return value indicates whether the inputted string matched the
// path. The first return value is meaningful only if the match was successful.
//
// If the match was a success, all parameterized segments in Path have a
// corresponding entry in the Params of Match. If the path allows for trailing
// segments in the input, these will be in Trailing.
func (p *Path) Match(s string) (Match, bool) {
	params := map[string]string{}

	for segmentIndex, segment := range p.Segments {
		// s[:i] is the prefix of s which contains the segment that must match
		// against the path. s[j:] is the suffix of s which the next iteration of
		// the loop will operate on.
		//
		// In "ordinary" circumstances, s[:i] is everything up to the first slash,
		// and s[j:] is everything after it. But when there are no remaining slashes
		// in the input, s[:i] is the entire string, and s[j:] is the empty string.
		i := strings.IndexByte(s, '/')
		j := i + 1
		if i == -1 {
			i = len(s)
			j = len(s)

			// If we have run out of slashes before the last element of the segments,
			// then the input does not match the path.
			//
			// Implicitly, allowing for trailing input effectively adds an additional
			// required slash to the input that's not captured by p.Segments. If
			// trailing input is allowed, it's never ok for an input to have fewer
			// slashes than the path has segments (an equal number is ok, and
			// corresponds to a trailing part with no slashes in it).
			if segmentIndex != len(p.Segments)-1 || p.Trailing {
				return Match{}, false
			}
		} else {
			// If we have slashes left over and we are not ok with trailing input,
			// then the input does not match the path.
			if segmentIndex == len(p.Segments)-1 && !p.Trailing {
				return Match{}, false
			}
		}

		if segment.IsParam {
			params[segment.Param] = s[:i]
		} else {
			if s[:i] != segment.Const {
				return Match{}, false
			}
		}

		s = s[j:]
	}

	return Match{Params: params, Trailing: s}, true
}

// Build is the inverse of Match. Given parameter and trailing segment
// information, Build returns a string which satifies this information.
//
// The second parameter indicates whether the inputted match has the parameters
// the path specifies. If any of the parameters in the path are not found in the
// provided Match's Params, then false is returned.
func (p *Path) Build(m Match) (string, bool) {
	var s strings.Builder
	for i, segment := range p.Segments {
		if segment.IsParam {
			if param, ok := m.Params[segment.Param]; ok {
				s.WriteString(param)
			} else {
				return "", false
			}
		} else {
			s.WriteString(segment.Const)
		}

		if i != len(p.Segments)-1 {
			s.WriteRune('/')
		}
	}

	// The trailing segment of a match does not include a leading slash. We
	// therefore need to add it here.
	//
	// However, if there are no segments at all in the path, then in this special
	// case the match's Trailing is simply the originally inputted string itself,
	// and so no leading slash must be inserted.
	if p.Trailing && len(p.Segments) > 0 {
		s.WriteRune('/')
	}

	s.WriteString(m.Trailing)

	return s.String(), true
}
