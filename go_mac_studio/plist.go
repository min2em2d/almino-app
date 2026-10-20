package main

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ParsePlistBytes parses an Apple XML plist into a Go map[string]interface{}.
func ParsePlistBytes(data []byte) (map[string]interface{}, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "plist" {
				val, err := parseNextPlistValue(dec)
				if err != nil {
					return nil, err
				}
				if m, ok := val.(map[string]interface{}); ok {
					return m, nil
				}
				return map[string]interface{}{"_root": val}, nil
			} else if se.Name.Local == "dict" {
				return parsePlistDict(dec)
			}
		}
	}
	return map[string]interface{}{}, nil
}

func parseNextPlistValue(dec *xml.Decoder) (interface{}, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return parsePlistElement(dec, t)
		case xml.EndElement:
			return nil, nil
		}
	}
}

func parsePlistElement(dec *xml.Decoder, se xml.StartElement) (interface{}, error) {
	switch se.Name.Local {
	case "dict":
		return parsePlistDict(dec)
	case "array":
		return parsePlistArray(dec)
	case "string", "key":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return "", err
		}
		return s, nil
	case "integer":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return int64(0), err
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return n, nil
	case "real":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return float64(0), err
		}
		f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, nil
	case "true":
		_ = dec.Skip()
		return true, nil
	case "false":
		_ = dec.Skip()
		return false, nil
	case "data":
		var s string
		if err := dec.DecodeElement(&s, &se); err != nil {
			return []byte{}, err
		}
		clean := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, s)
		raw, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			return []byte{}, nil
		}
		return raw, nil
	default:
		var s string
		_ = dec.DecodeElement(&s, &se)
		return s, nil
	}
}

func parsePlistDict(dec *xml.Decoder) (map[string]interface{}, error) {
	res := make(map[string]interface{})
	var currentKey string
	hasKey := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return res, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "key" {
				var k string
				if err := dec.DecodeElement(&k, &t); err != nil {
					return res, err
				}
				currentKey = k
				hasKey = true
			} else {
				val, err := parsePlistElement(dec, t)
				if err != nil {
					return res, err
				}
				if hasKey {
					res[currentKey] = val
					hasKey = false
				}
			}
		case xml.EndElement:
			if t.Name.Local == "dict" {
				return res, nil
			}
		}
	}
}

func parsePlistArray(dec *xml.Decoder) ([]interface{}, error) {
	var arr []interface{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return arr, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			val, err := parsePlistElement(dec, t)
			if err != nil {
				return arr, err
			}
			arr = append(arr, val)
		case xml.EndElement:
			if t.Name.Local == "array" {
				return arr, nil
			}
		}
	}
}

// BuildPlistXML serializes a Go map[string]interface{} into an Apple XML PropertyList.
func BuildPlistXML(root map[string]interface{}) []byte {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	buf.WriteString(`<plist version="1.0">` + "\n")
	writePlistValue(&buf, root, 0)
	buf.WriteString("\n</plist>\n")
	return buf.Bytes()
}

func writePlistValue(buf *bytes.Buffer, v interface{}, indent int) {
	pad := strings.Repeat("\t", indent)
	switch val := v.(type) {
	case map[string]interface{}:
		buf.WriteString(pad + "<dict>\n")
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			buf.WriteString(pad + "\t<key>" + escapeXML(k) + "</key>\n")
			writePlistValue(buf, val[k], indent+1)
			buf.WriteString("\n")
		}
		buf.WriteString(pad + "</dict>")
	case []string:
		buf.WriteString(pad + "<array>\n")
		for _, item := range val {
			buf.WriteString(pad + "\t<string>" + escapeXML(item) + "</string>\n")
		}
		buf.WriteString(pad + "</array>")
	case []interface{}:
		buf.WriteString(pad + "<array>\n")
		for _, item := range val {
			writePlistValue(buf, item, indent+1)
			buf.WriteString("\n")
		}
		buf.WriteString(pad + "</array>")
	case string:
		buf.WriteString(pad + "<string>" + escapeXML(val) + "</string>")
	case bool:
		if val {
			buf.WriteString(pad + "<true/>")
		} else {
			buf.WriteString(pad + "<false/>")
		}
	case int:
		buf.WriteString(fmt.Sprintf("%s<integer>%d</integer>", pad, val))
	case int64:
		buf.WriteString(fmt.Sprintf("%s<integer>%d</integer>", pad, val))
	case []byte:
		b64 := base64.StdEncoding.EncodeToString(val)
		buf.WriteString(pad + "<data>" + b64 + "</data>")
	default:
		buf.WriteString(pad + "<string>" + escapeXML(fmt.Sprintf("%v", val)) + "</string>")
	}
}

func escapeXML(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
