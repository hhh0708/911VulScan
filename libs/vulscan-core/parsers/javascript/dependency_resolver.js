#!/usr/bin/env node
/**
 * DependencyResolver - Resolves function dependencies for self-contained analysis units
 *
 * This component takes the analyzer output and:
 * 1. Builds a call graph by analyzing function bodies for call expressions
 * 2. Resolves function references to their definitions
 * 3. Collects transitive dependencies up to a configurable depth
 *
 * Usage:
 *   node dependency_resolver.js <analyzer_output.json> [--output <output.json>] [--depth <N>]
 *
 * Input: analyzer_output.json from typescript_analyzer.js
 * Output: Enhanced analyzer output with resolved call graph and dependency bundles
 */

const fs = require('fs');
const path = require('path');

class DependencyResolver {
  constructor(analyzerOutput, options = {}) {
    this.functions = analyzerOutput.functions || {};
    this.classes = analyzerOutput.classes || {};  // "filePath:className" -> { constructorDeps, fieldDeps, baseTypes }
    this.callGraph = {};  // functionId -> [calledFunctionIds]
    this.reverseCallGraph = {};  // functionId -> [callerFunctionIds]
    this.unresolvedEdges = [];  // [{caller, callee_name, reason, candidates}]
    this.maxDepth = options.maxDepth || 3;
    this.repoRoot = analyzerOutput.repoRoot || '';

    // Build indexes for faster lookup
    this.functionsByName = Object.create(null);  // simpleName -> [functionIds]
    this.functionsByFile = Object.create(null);  // filePath -> [functionIds]
    this.imports = analyzerOutput.imports || Object.create(null);  // filePath -> { importedName -> source }
    this.classesByBaseType = Object.create(null);  // baseTypeName -> ["filePath:className", ...]

    this._buildIndexes();
  }

  _recordUnresolved(callerId, calleeName, reason, candidates = []) {
    this.unresolvedEdges.push({
      caller: callerId,
      callee_name: calleeName,
      reason,
      candidates: candidates || [],
    });
  }

  /**
   * Build lookup indexes from function inventory
   */
  _buildIndexes() {
    for (const [funcId, funcData] of Object.entries(this.functions)) {
      // Index by simple name (last part of qualified name)
      const simpleName = funcData.name.split('.').pop();
      if (!this.functionsByName[simpleName]) {
        this.functionsByName[simpleName] = [];
      }
      this.functionsByName[simpleName].push(funcId);

      // Index by file path
      const filePath = funcId.split(':')[0];
      if (!this.functionsByFile[filePath]) {
        this.functionsByFile[filePath] = [];
      }
      this.functionsByFile[filePath].push(funcId);
    }

    for (const [classKey, classData] of Object.entries(this.classes)) {
      for (const baseType of (classData.baseTypes || [])) {
        if (!this.classesByBaseType[baseType]) this.classesByBaseType[baseType] = [];
        this.classesByBaseType[baseType].push(classKey);
      }
    }
  }

  /**
   * Build call graph by analyzing function bodies
   */
  buildCallGraph() {
    for (const [funcId, funcData] of Object.entries(this.functions)) {
      const calls = this._extractCalls(funcData.code, funcId);

      // Merge in any explicit call edges declared by the analyzer.
      // This is used for cases the body-text regex can't see — e.g.
      // Express middleware identifiers passed as sibling args:
      //   app.post('/x', authenticateToken, async (req,res) => {...})
      const explicitCalls = funcData.explicitCalls || [];
      const callerFile = funcId.split(':')[0];
      for (const name of explicitCalls) {
        if (!name) continue;
        const resolved = this._resolveCall(name, callerFile, funcId);
        if (resolved && !calls.includes(resolved)) {
          calls.push(resolved);
        }
      }

      this.callGraph[funcId] = calls;

      // Build reverse graph
      for (const calledId of calls) {
        if (!this.reverseCallGraph[calledId]) {
          this.reverseCallGraph[calledId] = [];
        }
        if (!this.reverseCallGraph[calledId].includes(funcId)) {
          this.reverseCallGraph[calledId].push(funcId);
        }
      }
    }

    return this.callGraph;
  }

  /**
   * Extract function calls from code and resolve to function IDs
   */
  _extractCalls(code, callerFuncId) {
    const calls = [];
    const callerFile = callerFuncId.split(':')[0];

    // Match function call patterns
    // 1. Simple calls: functionName(...)
    // 2. Method calls: object.method(...)
    // 3. Chained calls: object.method1().method2(...)
    // 4. Async/await calls: await functionName(...)

    const patterns = [
      // await asyncFunction(args)
      /await\s+([a-zA-Z_$][\w$]*)\s*\(/g,
      // this.method(args)
      /this\.([a-zA-Z_$][\w$]*)\s*\(/g,
      // object.method(args) - captures both object and method
      /([a-zA-Z_$][\w$]*)\.([a-zA-Z_$][\w$]*)\s*\(/g,
      // standalone function(args)
      /(?<![.\w$])([a-zA-Z_$][\w$]*)\s*\(/g,
    ];

    const seenCalls = new Set();

    // Pattern 1: await calls
    let match;
    const awaitPattern = /await\s+([a-zA-Z_$][\w$]*)\s*\(/g;
    while ((match = awaitPattern.exec(code)) !== null) {
      const funcName = match[1];
      const resolved = this._resolveCall(funcName, callerFile, callerFuncId);
      if (resolved && !seenCalls.has(resolved)) {
        seenCalls.add(resolved);
        calls.push(resolved);
      }
    }

    // Pattern 2: this.method calls (within the same class)
    const thisPattern = /this\.([a-zA-Z_$][\w$]*)\s*\(/g;
    while ((match = thisPattern.exec(code)) !== null) {
      const methodName = match[1];
      const resolved = this._resolveThisCall(methodName, callerFuncId);
      if (resolved && !seenCalls.has(resolved)) {
        seenCalls.add(resolved);
        calls.push(resolved);
      }
    }

    // Pattern 3: object.method calls
    const methodPattern = /([a-zA-Z_$][\w$]*)\.([a-zA-Z_$][\w$]*)\s*\(/g;
    while ((match = methodPattern.exec(code)) !== null) {
      const objectName = match[1];
      const methodName = match[2];

      // Skip 'this' (handled above) and common built-ins
      if (objectName === 'this' || this._isBuiltIn(objectName)) continue;

      const resolved = this._resolveMethodCall(objectName, methodName, callerFile, callerFuncId);
      if (resolved && !seenCalls.has(resolved)) {
        seenCalls.add(resolved);
        calls.push(resolved);
      }
    }

    // Pattern 4: standalone function calls
    const standalonePattern = /(?<![.\w$])([a-zA-Z_$][\w$]*)\s*\(/g;
    while ((match = standalonePattern.exec(code)) !== null) {
      const funcName = match[1];

      // Skip keywords and common built-ins
      if (this._isKeywordOrBuiltIn(funcName)) continue;

      const resolved = this._resolveCall(funcName, callerFile, callerFuncId);
      if (resolved && !seenCalls.has(resolved)) {
        seenCalls.add(resolved);
        calls.push(resolved);
      }
    }

    // Pattern 5: new Constructor(...)
    const newPattern = /\bnew\s+([a-zA-Z_$][\w$]*)\s*\(/g;
    while ((match = newPattern.exec(code)) !== null) {
      const ctorName = match[1];
      if (this._isKeywordOrBuiltIn(ctorName) || this._isBuiltIn(ctorName)) continue;
      // Prefer constructor unit id file:ClassName.constructor or ClassName
      const ctorCandidates = (this.functionsByName[ctorName] || []).concat(
        (this.functionsByName['constructor'] || []).filter(id => id.includes(`:${ctorName}.`))
      );
      const unique = [...new Set(ctorCandidates)];
      if (unique.length === 1) {
        if (!seenCalls.has(unique[0])) {
          seenCalls.add(unique[0]);
          calls.push(unique[0]);
        }
      } else {
        // Same-file class constructor
        const sameFile = unique.filter(id => id.startsWith(callerFile + ':'));
        if (sameFile.length === 1) {
          if (!seenCalls.has(sameFile[0])) {
            seenCalls.add(sameFile[0]);
            calls.push(sameFile[0]);
          }
        } else {
          this._recordUnresolved(
            callerFuncId,
            `new ${ctorName}`,
            unique.length > 1 ? 'ambiguous' : 'unresolved',
            unique
          );
        }
      }
    }

    return calls;
  }

  /**
   * Check if name is a JavaScript built-in object
   */
  _isBuiltIn(name) {
    const builtIns = new Set([
      'console', 'Math', 'JSON', 'Object', 'Array', 'String', 'Number',
      'Boolean', 'Date', 'RegExp', 'Error', 'Promise', 'Map', 'Set',
      'WeakMap', 'WeakSet', 'Symbol', 'Proxy', 'Reflect', 'Buffer',
      'process', 'global', 'window', 'document', 'localStorage',
      'sessionStorage', 'fetch', 'XMLHttpRequest', 'WebSocket',
      'URL', 'URLSearchParams', 'FormData', 'Headers', 'Request', 'Response'
    ]);
    return builtIns.has(name);
  }

  /**
   * Check if name is a keyword or built-in function
   */
  _isKeywordOrBuiltIn(name) {
    const keywords = new Set([
      'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break',
      'continue', 'return', 'throw', 'try', 'catch', 'finally',
      'function', 'class', 'const', 'let', 'var', 'new', 'delete',
      'typeof', 'instanceof', 'in', 'of', 'await', 'async', 'yield',
      'import', 'export', 'default', 'from', 'as', 'super', 'extends',
      // Built-in functions
      'require', 'parseInt', 'parseFloat', 'isNaN', 'isFinite',
      'encodeURI', 'decodeURI', 'encodeURIComponent', 'decodeURIComponent',
      'eval', 'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
      'setImmediate', 'clearImmediate', 'queueMicrotask'
    ]);
    return keywords.has(name);
  }

  /**
   * Resolve a simple function call to a function ID (scope-sensitive).
   * Never links by unique repo-wide name.
   */
  _resolveCall(funcName, callerFile, callerFuncId) {
    // 1. Same file
    const sameFileFuncs = this.functionsByFile[callerFile];
    const sameFileMatches = [];
    if (sameFileFuncs && Array.isArray(sameFileFuncs)) {
      for (const funcId of sameFileFuncs) {
        const funcData = this.functions[funcId];
        if (funcData && (funcData.name === funcName || funcData.name.endsWith('.' + funcName))) {
          sameFileMatches.push(funcId);
        }
      }
    }
    if (sameFileMatches.length === 1) return sameFileMatches[0];
    if (sameFileMatches.length > 1) {
      if (callerFuncId) {
        this._recordUnresolved(callerFuncId, funcName, 'ambiguous', sameFileMatches);
      }
      return null;
    }

    // 2. Import alias resolution (scope-sensitive)
    const fileImports = this.imports[callerFile] || {};
    if (fileImports[funcName]) {
      const importInfo = fileImports[funcName];
      const source = typeof importInfo === 'string' ? importInfo : (importInfo.source || importInfo);
      const original = typeof importInfo === 'object' ? (importInfo.originalName || funcName) : funcName;
      const candidates = (this.functionsByName[original] || []).filter(funcId => {
        const file = funcId.split(':')[0];
        return source && (file.includes(source.replace(/^\.\//, '')) || file.endsWith(source) ||
          file.replace(/\\/g, '/').includes(String(source).replace(/^\.\//, '').replace(/\\/g, '/')));
      });
      if (candidates.length === 1) return candidates[0];
      if (callerFuncId) {
        this._recordUnresolved(
          callerFuncId,
          funcName,
          candidates.length > 1 ? 'ambiguous' : 'import_failed',
          candidates
        );
      }
      return null;
    }

    // 3. No repo-wide unique-name linking
    const candidates = this.functionsByName[funcName] || [];
    if (callerFuncId && candidates.length) {
      this._recordUnresolved(
        callerFuncId,
        funcName,
        candidates.length > 1 ? 'ambiguous' : 'unresolved',
        candidates
      );
    } else if (callerFuncId) {
      this._recordUnresolved(callerFuncId, funcName, 'unresolved');
    }
    return null;
  }

  /**
   * Resolve a this.method call within a class
   */
  _resolveThisCall(methodName, callerFuncId) {
    // Extract class name from caller (e.g., "file.ts:ClassName.method" -> "ClassName")
    const callerFile = callerFuncId.split(':')[0];
    const callerFunc = this.functions[callerFuncId];

    if (callerFunc && callerFunc.className) {
      // Look for ClassName.methodName in same file
      const targetId = `${callerFile}:${callerFunc.className}.${methodName}`;
      if (this.functions[targetId]) {
        return targetId;
      }
    }

    return null;
  }

  /**
   * Resolve an object.method call
   *
   * Supports two resolution strategies:
   * 1. Direct class name match: objectName === className
   * 2. DI-aware resolution: objectName is a constructor-injected parameter,
   *    use its type annotation to find the target class
   */
  _resolveMethodCall(objectName, methodName, callerFile, callerFuncId = null) {
    const candidates = this.functionsByName[methodName];

    if (!candidates || !Array.isArray(candidates)) {
      if (callerFuncId) {
        this._recordUnresolved(callerFuncId, `${objectName}.${methodName}`, 'no_type');
      }
      return null;
    }

    // Resolve only via receiver static type (constructor/field type annotations).
    // Do NOT treat the variable name as a class name.
    if (callerFuncId) {
      const callerFunc = this.functions[callerFuncId];
      const classEntry = callerFunc && callerFunc.className &&
          this.classes[callerFile + ':' + callerFunc.className];
      if (classEntry && (classEntry.constructorDeps || classEntry.fieldDeps)) {
        const typeName = (classEntry.constructorDeps || {})[objectName]
            ?? (classEntry.fieldDeps || {})[objectName];
        if (typeName) {
          const typeMatches = candidates.filter(funcId => {
            const funcData = this.functions[funcId];
            return funcData && funcData.className === typeName;
          });
          if (typeMatches.length === 1) return typeMatches[0];

          const nominalClassKeys = this.classesByBaseType[typeName] || [];
          const nominalMatches = candidates.filter(funcId => {
            const funcData = this.functions[funcId];
            if (!funcData || !funcData.className) return false;
            const funcClassKey = funcId.split(':')[0] + ':' + funcData.className;
            return nominalClassKeys.includes(funcClassKey);
          });
          if (nominalMatches.length === 1) return nominalMatches[0];
          if (nominalMatches.length > 1 || typeMatches.length > 1) {
            this._recordUnresolved(
              callerFuncId,
              `${objectName}.${methodName}`,
              'ambiguous',
              typeMatches.length ? typeMatches : nominalMatches
            );
            return null;
          }
        }
      }
      this._recordUnresolved(callerFuncId, `${objectName}.${methodName}`, 'no_type', candidates);
    }

    return null;
  }

  /**
   * Get all dependencies for a function up to maxDepth
   */
  getDependencies(funcId, depth = null) {
    const maxD = depth !== null ? depth : this.maxDepth;
    const dependencies = new Set();
    const queue = [{ id: funcId, depth: 0 }];
    const visited = new Set([funcId]);

    while (queue.length > 0) {
      const { id, depth: currentDepth } = queue.shift();

      if (currentDepth >= maxD) continue;

      const calls = this.callGraph[id] || [];
      for (const calledId of calls) {
        if (!visited.has(calledId)) {
          visited.add(calledId);
          dependencies.add(calledId);
          queue.push({ id: calledId, depth: currentDepth + 1 });
        }
      }
    }

    return Array.from(dependencies);
  }

  /**
   * Get all callers (reverse dependencies) for a function
   */
  getCallers(funcId, depth = null) {
    const maxD = depth !== null ? depth : this.maxDepth;
    const callers = new Set();
    const queue = [{ id: funcId, depth: 0 }];
    const visited = new Set([funcId]);

    while (queue.length > 0) {
      const { id, depth: currentDepth } = queue.shift();

      if (currentDepth >= maxD) continue;

      const callerIds = this.reverseCallGraph[id] || [];
      for (const callerId of callerIds) {
        if (!visited.has(callerId)) {
          visited.add(callerId);
          callers.add(callerId);
          queue.push({ id: callerId, depth: currentDepth + 1 });
        }
      }
    }

    return Array.from(callers);
  }

  /**
   * Bundle dependencies for a function (for self-contained analysis)
   */
  bundleDependencies(funcId) {
    const deps = this.getDependencies(funcId);
    const bundle = {
      primary: {
        id: funcId,
        ...this.functions[funcId]
      },
      dependencies: []
    };

    for (const depId of deps) {
      const depFunc = this.functions[depId];
      if (depFunc) {
        bundle.dependencies.push({
          id: depId,
          name: depFunc.name,
          code: depFunc.code,
          unitType: depFunc.unitType,
          className: depFunc.className
        });
      }
    }

    return bundle;
  }

  /**
   * Get statistics about the call graph
   */
  getStatistics() {
    const stats = {
      totalFunctions: Object.keys(this.functions).length,
      totalEdges: 0,
      avgOutDegree: 0,
      avgInDegree: 0,
      maxOutDegree: 0,
      maxInDegree: 0,
      isolatedFunctions: 0,
      byUnitType: Object.create(null)
    };

    for (const [funcId, calls] of Object.entries(this.callGraph)) {
      const outDegree = calls.length;
      stats.totalEdges += outDegree;
      stats.maxOutDegree = Math.max(stats.maxOutDegree, outDegree);

      const inDegree = (this.reverseCallGraph[funcId] || []).length;
      stats.maxInDegree = Math.max(stats.maxInDegree, inDegree);

      if (outDegree === 0 && inDegree === 0) {
        stats.isolatedFunctions++;
      }

      // Count by unit type
      const unitType = this.functions[funcId]?.unitType || 'unknown';
      stats.byUnitType[unitType] = (stats.byUnitType[unitType] || 0) + 1;
    }

    const numFuncs = Object.keys(this.functions).length;
    stats.avgOutDegree = numFuncs > 0 ? (stats.totalEdges / numFuncs).toFixed(2) : 0;
    stats.avgInDegree = stats.avgOutDegree;  // Same for directed graphs

    return stats;
  }

  /**
   * Export enhanced output with resolved call graph
   */
  export() {
    // Body extraction is regex-based → never mark as exact confidence.
    const resolvedEdges = [];
    for (const [caller, callees] of Object.entries(this.callGraph)) {
      for (const callee of callees) {
        resolvedEdges.push({
          caller,
          callee,
          kind: 'call',
          confidence: 'low',
        });
      }
    }
    return {
      language: 'javascript',
      resolved_edges: resolvedEdges,
      unresolved_edges: this.unresolvedEdges,
      provenance: {
        builder: 'parsers.javascript.dependency_resolver',
        language: 'javascript',
        resolution: 'regex_fallback',
      },
      // In-memory legacy for unit_generator; file writes go through
      // Python write_call_graph which persists canonical fields only.
      functions: this.functions,
      call_graph: this.callGraph,
      reverse_call_graph: this.reverseCallGraph,
      callGraph: this.callGraph,
      reverseCallGraph: this.reverseCallGraph,
      statistics: this.getStatistics(),
      repoRoot: this.repoRoot,
    };
  }
}

// CLI execution
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: node dependency_resolver.js <analyzer_output.json> [--output <file>] [--depth <N>]');
    process.exit(1);
  }

  const inputFile = args[0];
  let outputFile = null;
  let maxDepth = 3;

  // Parse options
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--output' && i + 1 < args.length) {
      outputFile = args[++i];
    } else if (args[i] === '--depth' && i + 1 < args.length) {
      maxDepth = parseInt(args[++i], 10);
    }
  }

  // Load input
  if (!fs.existsSync(inputFile)) {
    console.error(`Input file not found: ${inputFile}`);
    process.exit(1);
  }

  const analyzerOutput = JSON.parse(fs.readFileSync(inputFile, 'utf-8'));

  // Build call graph
  console.error(`Processing ${Object.keys(analyzerOutput.functions || {}).length} functions...`);

  const resolver = new DependencyResolver(analyzerOutput, { maxDepth });
  resolver.buildCallGraph();

  const result = resolver.export();
  const stats = result.statistics;

  console.error(`Call graph built:`);
  console.error(`  Total functions: ${stats.totalFunctions}`);
  console.error(`  Total edges: ${stats.totalEdges}`);
  console.error(`  Avg out-degree: ${stats.avgOutDegree}`);
  console.error(`  Max out-degree: ${stats.maxOutDegree}`);
  console.error(`  Isolated functions: ${stats.isolatedFunctions}`);
  console.error(`  By unit type:`);
  for (const [type, count] of Object.entries(stats.byUnitType)) {
    console.error(`    - ${type}: ${count}`);
  }

  // Output
  const jsonOutput = JSON.stringify(result, null, 2);
  if (outputFile) {
    fs.writeFileSync(outputFile, jsonOutput);
    console.error(`Output written to ${outputFile}`);
  } else {
    console.log(jsonOutput);
  }
}

module.exports = { DependencyResolver };
