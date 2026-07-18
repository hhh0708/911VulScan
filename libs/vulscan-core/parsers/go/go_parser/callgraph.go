package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
)

// CallGraphBuilder builds call graphs from function information
type CallGraphBuilder struct {
	repoPath string
	fset     *token.FileSet

	// Indexes for resolution
	functionsByName map[string][]string // simple name -> [func_ids]
	functionsByFile map[string][]string // file_path -> [func_ids]
	methodsByType   map[string][]string // receiver_type -> [func_ids]

	// Import tracking per file
	importsByFile map[string]map[string]string // file -> alias -> package_path

	// Built-in functions to skip
	builtins map[string]bool
}

// NewCallGraphBuilder creates a new call graph builder
func NewCallGraphBuilder(repoPath string) *CallGraphBuilder {
	builtins := map[string]bool{
		// Built-in functions
		"append": true, "cap": true, "clear": true, "close": true, "complex": true,
		"copy": true, "delete": true, "imag": true, "len": true, "make": true,
		"max": true, "min": true, "new": true, "panic": true, "print": true,
		"println": true, "real": true, "recover": true,
		// Common stdlib that we don't want to trace
		"fmt":     true,
		"log":     true,
		"errors":  true,
		"strings": true,
		"strconv": true,
		"bytes":   true,
		"time":    true,
		"context": true,
		"sync":    true,
		"atomic":  true,
		"sort":    true,
		"math":    true,
		"io":      true,
		"os":      true,
		"path":    true,
		"regexp":  true,
		"json":    true,
		"xml":     true,
		"http":    true,
		"net":     true,
		"reflect": true,
		"runtime": true,
		"testing": true,
		"unsafe":  true,
	}

	return &CallGraphBuilder{
		repoPath:        repoPath,
		fset:            token.NewFileSet(),
		functionsByName: make(map[string][]string),
		functionsByFile: make(map[string][]string),
		methodsByType:   make(map[string][]string),
		importsByFile:   make(map[string]map[string]string),
		builtins:        builtins,
	}
}

// BuildCallGraph builds the call graph from extracted functions
func (c *CallGraphBuilder) BuildCallGraph(analyzer *AnalyzerOutput) (*CallGraph, error) {
	// Build indexes
	c.buildIndexes(analyzer)

	// Build the call graph
	callGraph := make(map[string][]string)
	reverseGraph := make(map[string][]string)
	var resolvedEdges []ResolvedEdge
	var unresolvedEdges []UnresolvedEdge

	totalEdges := 0
	maxOutDegree := 0

	for funcID, funcInfo := range analyzer.Functions {
		// Parse the function code to find calls
		calls := c.extractCalls(funcInfo)

		// Resolve calls to function IDs
		resolvedCalls, unresolved := c.resolveCalls(funcID, funcInfo, calls, analyzer)
		unresolvedEdges = append(unresolvedEdges, unresolved...)

		// Add to call graph
		if len(resolvedCalls) > 0 {
			callGraph[funcID] = resolvedCalls
			totalEdges += len(resolvedCalls)

			if len(resolvedCalls) > maxOutDegree {
				maxOutDegree = len(resolvedCalls)
			}

			// Build reverse graph
			for _, calledID := range resolvedCalls {
				reverseGraph[calledID] = append(reverseGraph[calledID], funcID)
				resolvedEdges = append(resolvedEdges, ResolvedEdge{
					Caller:     funcID,
					Callee:     calledID,
					Kind:       "call",
					Confidence: "exact",
				})
			}
		}
	}

	// Calculate statistics
	avgOutDegree := 0.0
	if len(analyzer.Functions) > 0 {
		avgOutDegree = float64(totalEdges) / float64(len(analyzer.Functions))
	}

	return &CallGraph{
		CallGraph:        callGraph,
		ReverseCallGraph: reverseGraph,
		ResolvedEdges:    resolvedEdges,
		UnresolvedEdges:  unresolvedEdges,
		Statistics: CallGraphStats{
			TotalEdges:   totalEdges,
			AvgOutDegree: avgOutDegree,
			MaxOutDegree: maxOutDegree,
			TotalNodes:   len(analyzer.Functions),
		},
	}, nil
}

func (c *CallGraphBuilder) buildIndexes(analyzer *AnalyzerOutput) {
	for funcID, funcInfo := range analyzer.Functions {
		// Index by simple name
		c.functionsByName[funcInfo.Name] = append(c.functionsByName[funcInfo.Name], funcID)

		// Index by file
		c.functionsByFile[funcInfo.FilePath] = append(c.functionsByFile[funcInfo.FilePath], funcID)

		// Index methods by receiver type
		if funcInfo.ClassName != "" {
			c.methodsByType[funcInfo.ClassName] = append(c.methodsByType[funcInfo.ClassName], funcID)
		}
	}

	// Parse imports for each unique file
	seenFiles := make(map[string]bool)
	for _, funcInfo := range analyzer.Functions {
		if seenFiles[funcInfo.FilePath] {
			continue
		}
		seenFiles[funcInfo.FilePath] = true

		fullPath := filepath.Join(c.repoPath, funcInfo.FilePath)
		c.parseImports(fullPath, funcInfo.FilePath)
	}
}

func (c *CallGraphBuilder) parseImports(fullPath, relPath string) {
	file, err := parser.ParseFile(c.fset, fullPath, nil, parser.ImportsOnly)
	if err != nil {
		return
	}

	imports := make(map[string]string)
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// Default alias is the last component of the path
			parts := strings.Split(path, "/")
			alias = parts[len(parts)-1]
		}
		imports[alias] = path
	}
	c.importsByFile[relPath] = imports
}

// CallInfo represents a function call found in code
type CallInfo struct {
	Name      string // Simple function name
	Receiver  string // Receiver for method calls (e.g., "obj" in obj.Method())
	Package   string // Package alias for package.Func() calls
	IsMethod  bool   // True if this is a method call
	IsSelf    bool   // True if receiver is "self" or matches current receiver
}

func (c *CallGraphBuilder) extractCalls(funcInfo FunctionInfo) []CallInfo {
	var calls []CallInfo

	// Parse the function code as a statement
	// We wrap it to make it parseable
	wrappedCode := "package p\n" + funcInfo.Code
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", wrappedCode, 0)
	if err != nil {
		return calls
	}

	// Walk the AST looking for call expressions
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		callInfo := c.analyzeCallExpr(call)
		if callInfo.Name != "" && !c.builtins[callInfo.Name] && !c.builtins[callInfo.Package] {
			calls = append(calls, callInfo)
		}
		return true
	})

	return calls
}

func (c *CallGraphBuilder) analyzeCallExpr(call *ast.CallExpr) CallInfo {
	info := CallInfo{}

	switch fun := call.Fun.(type) {
	case *ast.Ident:
		// Simple call: funcName()
		info.Name = fun.Name

	case *ast.SelectorExpr:
		// Method or package call: obj.Method() or pkg.Func()
		info.Name = fun.Sel.Name
		info.IsMethod = true

		switch x := fun.X.(type) {
		case *ast.Ident:
			info.Receiver = x.Name
			// Check if it looks like a package (lowercase) or object
			if isLikelyPackage(x.Name) {
				info.Package = x.Name
				info.IsMethod = false
			}

		case *ast.SelectorExpr:
			// Chained call: a.b.Method()
			info.Receiver = x.Sel.Name

		case *ast.CallExpr:
			// Result of another call: getObj().Method()
			info.Receiver = "~call_result~"
		}

	case *ast.IndexExpr:
		// Generic function call: fn[T]()
		if ident, ok := fun.X.(*ast.Ident); ok {
			info.Name = ident.Name
		}
	}

	return info
}

func isLikelyPackage(name string) bool {
	// Packages are typically lowercase
	if len(name) == 0 {
		return false
	}

	// Common patterns that are definitely packages
	packagePatterns := []string{
		"fmt", "log", "os", "io", "net", "http", "json", "xml",
		"strings", "strconv", "bytes", "time", "context", "sync",
		"errors", "filepath", "regexp", "math", "sort", "reflect",
	}
	for _, p := range packagePatterns {
		if name == p {
			return true
		}
	}

	// If all lowercase and short, likely a package
	first := rune(name[0])
	return first >= 'a' && first <= 'z' && len(name) <= 10
}

func receiverParamName(code string) string {
	// Parse "func (name *Type)" or "func (name Type)" from the method source.
	idx := strings.Index(code, "func (")
	if idx < 0 {
		return ""
	}
	rest := code[idx+len("func ("):]
	end := strings.Index(rest, ")")
	if end < 0 {
		return ""
	}
	parts := strings.Fields(rest[:end])
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}

func (c *CallGraphBuilder) resolveCalls(callerID string, callerInfo FunctionInfo, calls []CallInfo, analyzer *AnalyzerOutput) ([]string, []UnresolvedEdge) {
	var resolved []string
	var unresolved []UnresolvedEdge
	seen := make(map[string]bool)
	recvParam := receiverParamName(callerInfo.Code)

	for _, call := range calls {
		var targetID string
		var candidates []string
		reason := ""

		if call.Receiver == "~call_result~" {
			unresolved = append(unresolved, UnresolvedEdge{
				Caller: callerID, CalleeName: call.Name, Reason: "dynamic", Candidates: nil,
			})
			continue
		}

		// Self/receiver method: static type is the enclosing method's receiver type.
		isSelfCall := call.IsSelf ||
			(call.IsMethod && call.Package == "" && recvParam != "" && call.Receiver == recvParam) ||
			(call.IsMethod && call.Receiver != "" && call.Receiver == callerInfo.ClassName)

		if isSelfCall && callerInfo.ClassName != "" {
			targetID = c.resolveMethodCall(call.Name, callerInfo.ClassName, callerInfo.FilePath)
			if targetID == "" {
				reason = "no_type"
				candidates = c.methodsByType[callerInfo.ClassName]
			}
		} else if call.IsMethod && call.Receiver != "" && call.Package == "" {
			// Only resolve when Receiver is a known type name in methodsByType —
			// never treat an arbitrary variable name as a type.
			if _, ok := c.methodsByType[call.Receiver]; ok {
				targetID = c.resolveMethodCall(call.Name, call.Receiver, callerInfo.FilePath)
				if targetID == "" {
					reason = "no_type"
					candidates = c.methodsByType[call.Receiver]
				}
			} else if _, ok := c.methodsByType[strings.TrimPrefix(call.Receiver, "*")]; ok {
				targetID = c.resolveMethodCall(call.Name, call.Receiver, callerInfo.FilePath)
			} else {
				reason = "no_type"
			}
		} else if call.Package != "" {
			var ambig []string
			targetID, ambig = c.resolvePackageCall(call.Name, call.Package, callerInfo.FilePath, analyzer)
			if targetID == "" {
				if len(ambig) > 1 {
					reason = "ambiguous"
					candidates = ambig
				} else {
					reason = "import_failed"
					candidates = ambig
				}
			}
		} else {
			var ambig []string
			targetID, ambig = c.resolveSimpleCall(call.Name, callerInfo.FilePath, callerInfo.Package, analyzer)
			if targetID == "" {
				if len(ambig) > 1 {
					reason = "ambiguous"
					candidates = ambig
				} else if len(ambig) == 1 {
					reason = "unresolved"
					candidates = ambig
				} else {
					reason = "unresolved"
				}
			}
		}

		if targetID != "" && targetID != callerID && !seen[targetID] {
			resolved = append(resolved, targetID)
			seen[targetID] = true
		} else if targetID == "" && reason != "" {
			unresolved = append(unresolved, UnresolvedEdge{
				Caller:     callerID,
				CalleeName: call.Name,
				Reason:     reason,
				Candidates: candidates,
			})
		}
	}

	return resolved, unresolved
}

func (c *CallGraphBuilder) resolveMethodCall(methodName, receiverType, currentFile string) string {
	_ = currentFile
	matches := c.methodMatches(methodName, receiverType)
	if len(matches) == 1 {
		return matches[0]
	}
	return ""
}

func (c *CallGraphBuilder) methodMatches(methodName, receiverType string) []string {
	var matches []string
	seen := map[string]bool{}
	for _, rt := range []string{receiverType, strings.TrimPrefix(receiverType, "*")} {
		if methods, ok := c.methodsByType[rt]; ok {
			for _, funcID := range methods {
				if strings.HasSuffix(funcID, "."+methodName) && !seen[funcID] {
					matches = append(matches, funcID)
					seen[funcID] = true
				}
			}
		}
	}
	return matches
}

func (c *CallGraphBuilder) resolvePackageCall(funcName, pkgAlias, currentFile string, analyzer *AnalyzerOutput) (string, []string) {
	imports := c.importsByFile[currentFile]
	if imports == nil {
		return "", nil
	}

	pkgPath := imports[pkgAlias]
	if pkgPath == "" {
		return "", nil
	}

	var matches []string
	for _, funcID := range c.functionsByName[funcName] {
		info, ok := analyzer.Functions[funcID]
		if !ok {
			continue
		}
		// Match by package name (last path segment of import) or exact package field.
		base := pkgPath
		if idx := strings.LastIndex(pkgPath, "/"); idx >= 0 {
			base = pkgPath[idx+1:]
		}
		if info.Package == base || info.Package == pkgAlias || info.Package == pkgPath {
			matches = append(matches, funcID)
		}
	}
	if len(matches) == 1 {
		return matches[0], matches
	}
	return "", matches
}

func (c *CallGraphBuilder) resolveSimpleCall(funcName, currentFile, currentPkg string, analyzer *AnalyzerOutput) (string, []string) {
	// Priority 1: Same file
	var sameFile []string
	if funcs, ok := c.functionsByFile[currentFile]; ok {
		for _, funcID := range funcs {
			if strings.HasSuffix(funcID, ":"+funcName) {
				sameFile = append(sameFile, funcID)
			}
		}
	}
	if len(sameFile) == 1 {
		return sameFile[0], sameFile
	}
	if len(sameFile) > 1 {
		return "", sameFile
	}

	// Priority 2: Same package (different file) — scope-sensitive
	var samePkg []string
	for file, funcs := range c.functionsByFile {
		if filepath.Dir(file) != filepath.Dir(currentFile) {
			continue
		}
		for _, funcID := range funcs {
			info := analyzer.Functions[funcID]
			if info.Package != "" && currentPkg != "" && info.Package != currentPkg {
				continue
			}
			if strings.HasSuffix(funcID, ":"+funcName) {
				samePkg = append(samePkg, funcID)
			}
		}
	}
	if len(samePkg) == 1 {
		return samePkg[0], samePkg
	}
	if len(samePkg) > 1 {
		return "", samePkg
	}

	// No repo-wide unique-name linking
	candidates := c.functionsByName[funcName]
	return "", candidates
}
