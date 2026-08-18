package canonical

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Structures allowed to omit the leading Version field. A new entry is a deliberate,
// reviewable act, not a default.
var versionExempt = map[string]string{
	"ProposalV0":     "inherits SmartBFT's pre-existing frozen encoding; see proposal.go",
	"SignatureSetV0": "inherits SmartBFT's frozen PrevCommitSignatureDigest encoding; see signatures.go",
	"SignerSigV0":    "element of SignatureSetV0; same frozen encoding",
}

func parsePackage(t *testing.T) []*ast.File {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test source files found")
	}
	return files
}

// fieldTypeViolation returns the profile line a field type breaks, or "" if allowed.
func fieldTypeViolation(expr ast.Expr, declared map[string]bool) string {
	switch e := expr.(type) {
	case *ast.Ident:
		switch e.Name {
		case "int64", "bool":
			return ""
		case "string":
			return "string: the ASN.1 tag flips PrintableString <-> UTF8String on content"
		case "int":
			return "int: platform width"
		}
		if declared[e.Name] {
			return ""
		}
		if strings.HasPrefix(e.Name, "uint") || strings.HasPrefix(e.Name, "float") {
			return e.Name + ": unsupported by asn1.Marshal"
		}
		return e.Name + ": not one of []byte, int64, bool, or a struct declared in this package"
	case *ast.ArrayType:
		if e.Len != nil {
			return types.ExprString(e) + ": fixed-size arrays are unsupported by asn1.Marshal; use []byte"
		}
		elt, ok := e.Elt.(*ast.Ident)
		if !ok {
			return types.ExprString(e) + ": slice elements must be byte or a struct declared in this package"
		}
		if elt.Name == "byte" || declared[elt.Name] {
			return ""
		}
		return types.ExprString(e) + ": slice elements must be byte or a struct declared in this package"
	case *ast.MapType:
		return types.ExprString(e) + ": maps are unsupported by asn1.Marshal and iterate in unordered order"
	case *ast.StarExpr:
		return types.ExprString(e) + ": pointer fields are unsupported by asn1.Marshal"
	case *ast.SelectorExpr:
		return types.ExprString(e) + ": types from other packages are outside the profile (time.Time is banned)"
	default:
		return types.ExprString(e) + ": outside the profile"
	}
}

func TestTypeProfile(t *testing.T) {
	files := parsePackage(t)

	declared := map[string]bool{}
	type namedStruct struct {
		name string
		st   *ast.StructType
	}
	var exported []namedStruct
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				declared[ts.Name.Name] = true
				if ts.Name.IsExported() {
					exported = append(exported, namedStruct{ts.Name.Name, st})
				}
			}
		}
	}
	if len(exported) == 0 {
		t.Fatal("no exported struct types found; the guard would pass vacuously")
	}

	for _, s := range exported {
		fields := s.st.Fields.List
		if len(fields) == 0 {
			t.Errorf("%s: has no fields", s.name)
			continue
		}

		for i, f := range fields {
			if len(f.Names) == 0 {
				t.Errorf("%s: embedded field %s; every field must be named and exported",
					s.name, types.ExprString(f.Type))
				continue
			}
			for _, name := range f.Names {
				if !name.IsExported() {
					t.Errorf("%s.%s: unexported fields are a hard asn1.Marshal error", s.name, name.Name)
				}
			}
			if v := fieldTypeViolation(f.Type, declared); v != "" {
				t.Errorf("%s.%s: %s", s.name, f.Names[0].Name, v)
			}
			if f.Tag != nil {
				for _, banned := range []string{"optional", "set", "omitempty"} {
					if strings.Contains(f.Tag.Value, banned) {
						t.Errorf("%s.%s: struct tag %s carries %q, which is banned",
							s.name, f.Names[0].Name, f.Tag.Value, banned)
					}
				}
			}

			if i != 0 {
				continue
			}
			if _, exempt := versionExempt[s.name]; exempt {
				continue
			}
			if f.Names[0].Name != "Version" || types.ExprString(f.Type) != "int64" {
				t.Errorf("%s: V-RULE requires the first field to be Version int64, got %s %s",
					s.name, f.Names[0].Name, types.ExprString(f.Type))
			}
		}
	}
}

func TestZeroDependencies(t *testing.T) {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	modulePath := ""
	for _, line := range strings.Split(string(mod), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "module "):
			modulePath = strings.TrimSpace(strings.TrimPrefix(line, "module "))
		case strings.HasPrefix(line, "require"), strings.HasPrefix(line, "replace"):
			t.Errorf("go.mod carries a %q directive; canonical must depend on nothing", line)
		}
	}
	if modulePath == "" {
		t.Fatal("go.mod declares no module path")
	}

	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	var external []string
	for _, dep := range strings.Fields(string(out)) {
		if dep == modulePath || strings.HasPrefix(dep, modulePath+"/") {
			continue
		}
		// A stdlib import path's first segment is not a domain, so it has no dot.
		if strings.Contains(strings.SplitN(dep, "/", 2)[0], ".") {
			external = append(external, dep)
		}
	}
	if len(external) != 0 {
		t.Errorf("non-stdlib dependencies: %s", strings.Join(external, ", "))
	}
}
