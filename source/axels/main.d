module axels.main;

import std.stdio;
import std.json;
import std.string;
import std.conv;
import std.exception;
import std.process;
import std.file;
import std.algorithm;
import std.path;

/** 
 * Some LSP request to the server.
 */
struct LspRequest
{
    string jsonrpc;
    string method;
    JSONValue id;
    JSONValue params;
}

/** 
 * Some diagnostic from the server.
 */
struct Diagnostic
{
    string message;
    string fileName;
    size_t line;
    size_t column;
}

__gshared string[string] g_openDocs;
__gshared bool g_debugMode = false;
__gshared string g_stdlibPath = "";

void debugLog(T...)(T args)
{
    if (g_debugMode)
    {
        stderr.writeln("[DEBUG] ", args);
        stderr.flush();
    }
}

string uriToPath(string uri)
{
    enum prefix = "file://";
    if (uri.startsWith(prefix))
    {
        string path = uri[prefix.length .. $];
        version (Windows)
        {
            if (path.length > 0 && path[0] == '/')
            {
                path = path[1 .. $];
            }
        }
        return path;
    }
    return uri;
}

string wordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

string extractWordAt(string text, size_t line0, size_t char0)
{
    auto lines = text.splitLines();
    if (line0 >= lines.length)
    {
        return "";
    }

    auto line = lines[line0];
    if (char0 >= line.length)
    {
        if (line.length == 0)
            return "";
        char0 = cast(size_t)(cast(int) line.length - 1);
    }

    size_t start = char0;
    while (start > 0 && wordChars.canFind(line[start - 1]))
    {
        --start;
    }
    size_t end = char0;
    while (end < line.length && wordChars.canFind(line[end]))
    {
        ++end;
    }
    return line[start .. end];
}

Diagnostic[] parseDiagnostics(string text)
{
    Diagnostic[] result;
    foreach (line; text.splitLines())
    {
        auto trimmed = line.strip();
        if (trimmed.length == 0)
        {
            continue;
        }

        auto first = trimmed.countUntil(':');
        if (first <= 0)
        {
            continue;
        }
        auto second = trimmed.countUntil(':', first + 1);
        if (second <= 0)
        {
            continue;
        }
        auto third = trimmed.countUntil(':', second + 1);
        if (third <= 0)
        {
            continue;
        }

        string fileName = trimmed[0 .. first];
        string lineStr = trimmed[first + 1 .. second];
        string colStr = trimmed[second + 1 .. third];
        string msg = trimmed[third + 1 .. $].strip();

        size_t ln, col;
        try
        {
            ln = to!size_t(lineStr.strip());
            col = to!size_t(colStr.strip());
        }
        catch (Exception)
        {
            continue;
        }

        Diagnostic d;
        d.fileName = fileName;
        d.line = ln;
        d.column = col;
        d.message = msg;
        result ~= d;
    }
    return result;
}

Diagnostic[] runCompilerOn(string uri, string text)
{
    string path = uriToPath(uri);
    debugLog("Running compiler on: ", path);

    try
    {
        std.file.write(path, text);
    }
    catch (Exception e)
    {
        debugLog("Failed to write file: ", e.msg);
        return Diagnostic[].init;
    }

    Diagnostic[] diags;
    try
    {
        auto result = execute(["axc", path]);
        debugLog("Compiler output: ", result.output);
        diags ~= parseDiagnostics(result.output);
        debugLog("Parsed ", diags.length, " diagnostics");
    }
    catch (Exception e)
    {
        debugLog("Compiler execution failed: ", e.msg);
    }
    return diags;
}

void sendDiagnostics(string uri, Diagnostic[] diags)
{
    debugLog("Sending ", diags.length, " diagnostics for ", uri);

    JSONValue root;
    root["jsonrpc"] = "2.0";
    root["method"] = "textDocument/publishDiagnostics";

    JSONValue params;
    params["uri"] = uri;

    JSONValue[] arr;
    foreach (d; diags)
    {
        JSONValue jd;
        JSONValue rng;
        JSONValue sPos;
        JSONValue ePos;

        long l = cast(long)(d.line > 0 ? d.line - 1 : 0);
        long ch = cast(long)(d.column > 0 ? d.column - 1 : 0);

        sPos["line"] = l;
        sPos["character"] = ch;
        ePos["line"] = l;
        ePos["character"] = ch + 1;

        rng["start"] = sPos;
        rng["end"] = ePos;

        jd["range"] = rng;
        jd["message"] = d.message;
        jd["severity"] = 1L;

        arr ~= jd;
    }

    params["diagnostics"] = JSONValue(arr);
    root["params"] = params;

    writeMessage(root.toString());
}

string readMessage()
{
    size_t contentLength;

    while (true)
    {
        if (stdin.eof)
        {
            debugLog("stdin EOF reached");
            return null;
        }
        string line = stdin.readln();
        if (line is null)
        {
            debugLog("readln returned null");
            return null;
        }
        line = line.stripRight("\r\n");
        debugLog("Header line: '", line, "'");
        if (line.length == 0)
        {
            break;
        }
        auto lower = line.toLower();
        enum prefix = "content-length:";
        if (lower.startsWith(prefix))
        {
            auto value = line[prefix.length .. $].strip();
            contentLength = to!size_t(value);
            debugLog("Content-Length: ", contentLength);
        }
    }

    if (contentLength == 0)
    {
        debugLog("No content length found");
        return null;
    }

    ubyte[] buf;
    buf.length = contentLength;
    size_t readBytes = 0;
    while (readBytes < contentLength)
    {
        auto chunk = stdin.rawRead(buf[readBytes .. $]);
        auto n = chunk.length;
        if (n == 0)
            break;
        readBytes += n;
    }

    string result = cast(string) buf[0 .. readBytes];
    debugLog("Received message: ", result);
    return result;
}

void writeMessage(string payload)
{
    import std.stdio : stdout;

    auto bytes = cast(const(ubyte)[]) payload;

    string header = "Content-Length: " ~ to!string(bytes.length) ~ "\r\n\r\n";
    auto headerBytes = cast(const(ubyte)[]) header;

    debugLog("Writing header: ", header.strip());
    debugLog("Writing payload (", bytes.length, " bytes)");

    stdout.rawWrite(headerBytes);
    stdout.rawWrite(bytes);
    stdout.flush();

    debugLog("Write completed and flushed");
}

LspRequest parseRequest(string body)
{
    auto j = parseJSON(body);
    LspRequest req;
    if (j.type == JSONType.object)
    {
        auto obj = j.object;
        if ("jsonrpc" in obj)
            req.jsonrpc = obj["jsonrpc"].str;
        if ("method" in obj)
            req.method = obj["method"].str;
        if ("id" in obj)
            req.id = obj["id"];
        if ("params" in obj)
            req.params = obj["params"];
    }
    return req;
}

void sendResponse(JSONValue id, JSONValue result)
{
    JSONValue root;
    root["jsonrpc"] = "2.0";
    root["id"] = id;
    root["result"] = result;

    // Convert to string with proper formatting
    string payload = root.toString();
    debugLog("Sending response with id=", id.toString());
    debugLog("Full response: ", payload);
    writeMessage(payload);
}

void sendError(JSONValue id, int code, string message)
{
    JSONValue root;
    root["jsonrpc"] = "2.0";
    root["id"] = id;

    JSONValue err;
    err["code"] = code;
    err["message"] = message;
    root["error"] = err;

    writeMessage(root.toString());
}

void handleInitialize(LspRequest req)
{
    debugLog("Handling initialize request");

    try
    {
        string response = `{"jsonrpc":"2.0","id":` ~ req.id.toString() ~
            `,"result":{"capabilities":` ~
            `{"textDocumentSync":1,"hoverProvider":true,"definitionProvider":true,` ~
            `"completionProvider":{"triggerCharacters":["."]},"documentSymbolProvider":true}}}`;
        debugLog("Sending initialize response");
        debugLog("Response: ", response);
        writeMessage(response);
        debugLog("Initialize response sent successfully");
        stderr.writeln("[INFO] Sent initialize response");
        stderr.flush();
    }
    catch (Exception e)
    {
        debugLog("Error in handleInitialize: ", e.msg);
        stderr.writeln("[ERROR] Failed to send initialize response: ", e.msg);
        stderr.flush();
    }
}

void handleInitialized(LspRequest req)
{
    debugLog("Client initialized notification received");

    // Log that we're ready to receive requests
    stderr.writeln("[INFO] LSP server is now ready to handle requests");
    stderr.flush();
}

void handleShutdown(LspRequest req)
{
    debugLog("Shutdown request received");
    JSONValue nilResult;
    sendResponse(req.id, nilResult);
}

void handleExit(LspRequest req)
{
    debugLog("Exit notification received");
    import core.stdc.stdlib : exit;

    exit(0);
}

void handleDidOpen(LspRequest req)
{
    debugLog("Handling didOpen");

    auto params = req.params;
    if (params.type != JSONType.object)
    {
        debugLog("didOpen: params not an object");
        return;
    }

    auto pObj = params.object;
    if (!("textDocument" in pObj))
    {
        debugLog("didOpen: no textDocument in params");
        return;
    }

    auto td = pObj["textDocument"];
    if (td.type != JSONType.object)
    {
        debugLog("didOpen: textDocument not an object");
        return;
    }

    auto tdObj = td.object;
    if (!("uri" in tdObj) || !("text" in tdObj))
    {
        debugLog("didOpen: missing uri or text");
        return;
    }

    string uri = tdObj["uri"].str;
    string text = tdObj["text"].str;

    debugLog("didOpen: uri=", uri, ", text length=", text.length);
    g_openDocs[uri] = text;

    auto diags = runCompilerOn(uri, text);
    sendDiagnostics(uri, diags);
}

void handleDidChange(LspRequest req)
{
    debugLog("Handling didChange");

    auto params = req.params;
    if (params.type != JSONType.object)
    {
        debugLog("didChange: params not an object");
        return;
    }

    auto pObj = params.object;
    if (!("textDocument" in pObj))
    {
        debugLog("didChange: no textDocument in params");
        return;
    }

    auto td = pObj["textDocument"];
    if (td.type != JSONType.object)
    {
        debugLog("didChange: textDocument not an object");
        return;
    }

    auto tdObj = td.object;
    if (!("uri" in tdObj))
    {
        debugLog("didChange: no uri in textDocument");
        return;
    }

    string uri = tdObj["uri"].str;

    if (!("contentChanges" in pObj))
    {
        debugLog("didChange: no contentChanges in params");
        return;
    }

    auto changes = pObj["contentChanges"];
    if (changes.type != JSONType.array || changes.array.length == 0)
    {
        debugLog("didChange: contentChanges not an array or empty");
        return;
    }

    // For textDocumentSync = 1 (Full), the last change contains the full text
    auto change = changes.array[$ - 1];
    if (change.type != JSONType.object)
    {
        debugLog("didChange: change not an object");
        return;
    }

    auto chObj = change.object;
    if (!("text" in chObj))
    {
        debugLog("didChange: no text in change");
        return;
    }

    string text = chObj["text"].str;
    debugLog("didChange: uri=", uri, ", new text length=", text.length);
    g_openDocs[uri] = text;

    // Run diagnostics on the updated text
    auto diags = runCompilerOn(uri, text);
    sendDiagnostics(uri, diags);
}

void handleDidSave(LspRequest req)
{
    debugLog("Handling didSave");

    auto params = req.params;
    if (params.type != JSONType.object)
    {
        return;
    }

    auto pObj = params.object;
    if (!("textDocument" in pObj))
    {
        return;
    }

    auto td = pObj["textDocument"];
    if (td.type != JSONType.object)
    {
        return;
    }

    auto tdObj = td.object;
    if (!("uri" in tdObj))
    {
        return;
    }

    string uri = tdObj["uri"].str;
    debugLog("didSave: uri=", uri);

    auto it = uri in g_openDocs;
    if (it !is null)
    {
        auto diags = runCompilerOn(uri, *it);
        sendDiagnostics(uri, diags);
    }
}

void handleDidClose(LspRequest req)
{
    debugLog("Handling didClose");

    auto params = req.params;
    if (params.type != JSONType.object)
    {
        return;
    }

    auto pObj = params.object;
    if (!("textDocument" in pObj))
    {
        return;
    }

    auto td = pObj["textDocument"];
    if (td.type != JSONType.object)
    {
        return;
    }

    auto tdObj = td.object;
    if (!("uri" in tdObj))
    {
        return;
    }

    string uri = tdObj["uri"].str;
    debugLog("didClose: uri=", uri);

    auto it = uri in g_openDocs;
    if (it !is null)
    {
        g_openDocs.remove(uri);
    }

    sendDiagnostics(uri, Diagnostic[].init);
}

string[] axeKeywords = [
    "def", "pub", "mut", "val", "loop", "for", "in", "if", "else",
    "elif", "switch", "case", "break", "continue", "model", "enum",
    "use", "test", "assert", "unsafe", "parallel", "single", "platform",
    "return", "import", "export", "ref", "as", "from"
];

string[] axeTypes = [
    "string", "i32", "i64", "u32", "u64", "usize", "f32", "f64",
    "bool", "void", "char", "i8", "i16", "u8", "u16"
];

string[] axeBuiltins = [
    "println", "print", "print_str", "str", "concat", "substr", "strip",
    "read_file", "write_file", "file_exists", "delete_file", "is_directory",
    "exec_from_string", "get_cmdline_args", "ref_of", "Arena", "StringList",
    "compare", "find_char_from", "has_suffix", "trim_suffix", "addr"
];

enum SymbolKind
{
    Unknown,
    Keyword,
    Type,
    Function,
    Variable,
    Builtin,
    Model,
    Property
}

struct SymbolInfo
{
    string name;
    SymbolKind kind;
    string context;
    string doc;
}

/// Represents a field in a model
struct ModelField
{
    string name;
    string type;
    string doc;
}

/// Represents a method in a model
struct ModelMethod
{
    string name;
    string signature;
    string doc;
    bool isStatic;
}

/// Represents a parsed model definition
struct ModelDef
{
    string name;
    ModelField[] fields;
    ModelMethod[] methods;
    string doc;
}

/// Global cache of parsed models
__gshared ModelDef[string] g_modelCache;

/// Parses all models from text and returns them
ModelDef[] parseModelsFromText(string text)
{
    ModelDef[] models;
    auto lines = text.splitLines();

    for (size_t i = 0; i < lines.length; i++)
    {
        auto line = lines[i].strip();

        bool isPub = line.startsWith("pub model ");
        bool isModel = isPub || line.startsWith("model ");

        if (isModel)
        {
            ModelDef model;

            size_t nameStart = isPub ? 10 : 6;
            auto restOfLine = line[nameStart .. $].strip();
            size_t nameEnd = 0;
            while (nameEnd < restOfLine.length && wordChars.canFind(restOfLine[nameEnd]))
                nameEnd++;
            model.name = restOfLine[0 .. nameEnd];

            model.doc = getDocStringAboveLine(lines, i);
            size_t braceStart = i;
            while (braceStart < lines.length && !lines[braceStart].canFind("{"))
                braceStart++;

            if (braceStart >= lines.length)
                continue;

            int braceCount = 0;
            bool inModel = false;
            string currentDoc = "";

            for (size_t j = braceStart; j < lines.length; j++)
            {
                auto modelLine = lines[j];
                foreach (ch; modelLine)
                {
                    if (ch == '{')
                        braceCount++;
                    else if (ch == '}')
                        braceCount--;
                }

                if (braceCount > 0)
                    inModel = true;

                auto trimmed = modelLine.strip();

                if (trimmed.startsWith("///"))
                {
                    if (currentDoc.length > 0)
                        currentDoc ~= "\n";
                    currentDoc ~= trimmed[3 .. $].strip();
                    continue;
                }

                if (inModel && braceCount == 1 && trimmed.length > 0 &&
                    !trimmed.startsWith("def ") && !trimmed.startsWith("pub def ") &&
                    !trimmed.startsWith("//") && !trimmed.startsWith("{") && !trimmed.startsWith(
                        "}"))
                {
                    auto colonIdx = trimmed.indexOf(":");
                    if (colonIdx > 0)
                    {
                        auto fieldName = trimmed[0 .. colonIdx].strip();
                        auto afterColon = trimmed[colonIdx + 1 .. $].strip();

                        if (afterColon.length > 0 && afterColon[$ - 1] == ';')
                            afterColon = afterColon[0 .. $ - 1].strip();

                        if (!afterColon.canFind("(") && fieldName.length > 0 &&
                            wordChars.canFind(fieldName[0]))
                        {
                            ModelField field;
                            field.name = cast(string) fieldName;
                            field.type = cast(string) afterColon;
                            field.doc = currentDoc;
                            model.fields ~= field;
                        }
                    }
                    currentDoc = "";
                }

                bool isPubDef = trimmed.startsWith("pub def ");
                bool isDef = isPubDef || trimmed.startsWith("def ");

                if (inModel && isDef)
                {
                    ModelMethod method;
                    size_t defStart = isPubDef ? 8 : 4;
                    auto methodRest = trimmed[defStart .. $].strip();

                    size_t methodNameEnd = 0;
                    while (methodNameEnd < methodRest.length && wordChars.canFind(
                            methodRest[methodNameEnd]))
                        methodNameEnd++;
                    method.name = cast(string) methodRest[0 .. methodNameEnd];

                    auto parenStart = methodRest.indexOf("(");
                    if (parenStart >= 0)
                    {
                        int parenCount = 0;
                        size_t sigEnd = parenStart;
                        for (size_t k = parenStart; k < methodRest.length; k++)
                        {
                            if (methodRest[k] == '(')
                                parenCount++;
                            else if (methodRest[k] == ')')
                                parenCount--;
                            if (parenCount == 0)
                            {
                                sigEnd = k + 1;
                                break;
                            }
                        }

                        if (sigEnd < methodRest.length)
                        {
                            auto afterParen = methodRest[sigEnd .. $].strip();
                            if (afterParen.startsWith(":"))
                            {
                                size_t retEnd = 1;
                                while (retEnd < afterParen.length &&
                                    afterParen[retEnd] != '{' && afterParen[retEnd] != ';')
                                    retEnd++;
                                method.signature = cast(string)(
                                    methodRest[0 .. sigEnd] ~ afterParen[0 .. retEnd]);
                            }
                            else
                            {
                                method.signature = cast(string) methodRest[0 .. sigEnd];
                            }
                        }
                        else
                        {
                            method.signature = cast(string) methodRest[0 .. sigEnd];
                        }

                        auto paramSection = methodRest[parenStart + 1 .. sigEnd - 1];
                        method.isStatic = true;
                        if (paramSection.canFind("ref " ~ model.name) ||
                            paramSection.canFind(": " ~ model.name))
                        {
                            method.isStatic = false;
                        }
                    }

                    method.doc = currentDoc;
                    model.methods ~= method;
                    currentDoc = "";
                }
                else if (!trimmed.startsWith("///"))
                {
                    currentDoc = "";
                }

                if (braceCount == 0 && inModel)
                    break;
            }

            models ~= model;
        }
    }

    return models;
}

/// Gets all models from a document (caches results)
ModelDef[] getModelsForDocument(string uri, string text)
{
    return parseModelsFromText(text);
}

/// Find the type of a variable at a given position
string findVariableType(string text, string varName, size_t line0, size_t char0)
{
    auto lines = text.splitLines();

    for (long i = cast(long) line0; i >= 0; i--)
    {
        auto line = lines[i];

        auto valPattern = "val " ~ varName ~ ":";
        auto mutPattern = "mut " ~ varName ~ ":";

        auto valIdx = line.indexOf(valPattern);
        auto mutIdx = line.indexOf(mutPattern);

        long foundIdx = -1;
        size_t patternLen = 0;

        if (valIdx >= 0)
        {
            foundIdx = valIdx;
            patternLen = valPattern.length;
        }
        else if (mutIdx >= 0)
        {
            foundIdx = mutIdx;
            patternLen = mutPattern.length;
        }

        if (foundIdx >= 0)
        {
            auto afterColon = line[foundIdx + patternLen .. $].strip();

            size_t typeEnd = 0;
            while (typeEnd < afterColon.length &&
                (wordChars.canFind(afterColon[typeEnd]) || afterColon[typeEnd] == '*'))
                typeEnd++;

            if (typeEnd > 0)
            {
                auto typeName = afterColon[0 .. typeEnd];
                if (typeName == "ref" && typeEnd < afterColon.length)
                {
                    auto rest = afterColon[typeEnd .. $].strip();
                    typeEnd = 0;
                    while (typeEnd < rest.length && wordChars.canFind(rest[typeEnd]))
                        typeEnd++;
                    return cast(string) rest[0 .. typeEnd];
                }
                return cast(string) typeName;
            }
        }

        auto paramPattern = varName ~ ":";
        auto paramIdx = line.indexOf(paramPattern);
        if (paramIdx >= 0)
        {
            if (paramIdx > 0 && wordChars.canFind(line[paramIdx - 1]))
                continue;

            auto afterColon = line[paramIdx + paramPattern.length .. $].strip();
            size_t typeEnd = 0;
            while (typeEnd < afterColon.length &&
                (wordChars.canFind(afterColon[typeEnd]) || afterColon[typeEnd] == '*'))
                typeEnd++;

            if (typeEnd > 0)
            {
                auto typeName = afterColon[0 .. typeEnd];
                if (typeName == "ref" && typeEnd < afterColon.length)
                {
                    auto rest = afterColon[typeEnd .. $].strip();
                    typeEnd = 0;
                    while (typeEnd < rest.length && wordChars.canFind(rest[typeEnd]))
                        typeEnd++;
                    return cast(string) rest[0 .. typeEnd];
                }
                return cast(string) typeName;
            }
        }
    }

    return "";
}

/// Extract the word before the dot at a given position
string extractWordBeforeDot(string text, size_t line0, size_t char0)
{
    auto lines = text.splitLines();
    if (line0 >= lines.length)
        return "";

    auto line = lines[line0];
    if (char0 == 0 || char0 > line.length)
        return "";

    long dotPos = cast(long) char0 - 1;
    while (dotPos >= 0 && line[dotPos] == ' ')
        dotPos--;

    if (dotPos < 0 || line[dotPos] != '.')
    {
        if (char0 < line.length && line[char0] == '.')
            dotPos = char0;
        else if (char0 > 0 && line[char0 - 1] == '.')
            dotPos = cast(long) char0 - 1;
        else
            return "";
    }

    long wordEnd = dotPos;
    long wordStart = wordEnd - 1;
    while (wordStart >= 0 && wordChars.canFind(line[wordStart]))
        wordStart--;
    wordStart++;

    if (wordStart >= wordEnd)
        return "";

    return cast(string) line[wordStart .. wordEnd];
}

/// Get the standard library path
string getStdLibPath()
{
    import std.process : environment;
    import std.path : buildPath, dirName;

    if (g_stdlibPath.length > 0)
    {
        return g_stdlibPath;
    }

    auto axeHome = environment.get("AXE_HOME", "");
    if (axeHome.length > 0)
    {
        return buildPath(axeHome, "std");
    }

    version (Windows)
    {
        return "C:\\axe\\std";
    }
    else
    {
        return "/usr/local/lib/axe/std";
    }
}

/// Load models from standard library
ModelDef[] loadStdLibModels()
{
    ModelDef[] models;

    string stdPath = getStdLibPath();
    debugLog("Looking for std lib at: ", stdPath);

    try
    {
        import std.file : dirEntries, SpanMode, readText, exists;

        if (!exists(stdPath))
        {
            debugLog("Std lib path does not exist");
            return models;
        }

        foreach (entry; dirEntries(stdPath, "*.axec", SpanMode.shallow))
        {
            try
            {
                string content = readText(entry.name);
                auto parsed = parseModelsFromText(content);
                models ~= parsed;
                debugLog("Loaded ", parsed.length, " models from ", entry.name);
            }
            catch (Exception e)
            {
                debugLog("Failed to parse ", entry.name, ": ", e.msg);
            }
        }
    }
    catch (Exception e)
    {
        debugLog("Failed to load std lib: ", e.msg);
    }

    return models;
}

string[] getSearchDirectories(string currentPath)
{
    string[] searchDirs;
    string startDir = currentPath;
    try
    {
        import std.path : dirName, buildPath, extension;

        if (exists(currentPath) && isFile(currentPath))
            startDir = dirName(currentPath);
    }
    catch (Exception)
    {
        startDir = ".";
    }

    string projectRoot = "";
    string curr = startDir;
    try
    {
        while (true)
        {
            if (exists(buildPath(curr, "axe.mod")))
            {
                projectRoot = curr;
                break;
            }
            string parent = dirName(curr);
            version (Windows)
            {
                if (parent == curr)
                    break;
            }
            else
            {
                if (parent == curr)
                    break;
            }
            curr = parent;
        }
    }
    catch (Exception)
    {
    }

    if (projectRoot.length > 0)
        searchDirs ~= projectRoot;
    else
        searchDirs ~= startDir;

    string axeHome = environment.get("AXE_HOME", "");
    if (axeHome.length > 0)
    {
        try
        {
            if (exists(axeHome) && isDir(axeHome))
            {
                searchDirs ~= axeHome;
            }
        }
        catch (Exception)
        {
        }
    }

    return searchDirs;
}

ModelDef[] loadProjectModels(string currentPath)
{
    ModelDef[] allModels;
    string[] searchDirs = getSearchDirectories(currentPath);

    import std.file : dirEntries;
    import std.file : SpanMode;

    foreach (dir; searchDirs)
    {
        try
        {
            foreach (dirEntry; dirEntries(dir, SpanMode.depth))
            {
                if (!dirEntry.isFile)
                    continue;
                auto ext = dirEntry.name.split('.');
                if (ext.length == 0)
                    continue;
                auto fileExt = "." ~ ext[$ - 1];
                if (fileExt != ".axe" && fileExt != ".axec")
                    continue;

                string fileText;
                try
                {
                    fileText = readText(dirEntry.name);
                }
                catch (Exception)
                {
                    continue;
                }

                auto models = parseModelsFromText(fileText);
                allModels ~= models;
            }
        }
        catch (Exception)
        {
            continue;
        }
    }
    return allModels;
}

SymbolInfo analyzeSymbol(string word, string fullText, size_t line0, size_t char0, string currentUri)
{
    SymbolInfo info;
    info.name = word;
    info.kind = SymbolKind.Unknown;

    foreach (kw; axeKeywords)
    {
        if (word == kw)
        {
            info.kind = SymbolKind.Keyword;
            return info;
        }
    }

    foreach (ty; axeTypes)
    {
        if (word == ty)
        {
            info.kind = SymbolKind.Type;
            return info;
        }
    }

    foreach (bi; axeBuiltins)
    {
        if (word == bi)
        {
            info.kind = SymbolKind.Builtin;
            return info;
        }
    }

    auto lines = fullText.splitLines();
    if (line0 < lines.length)
    {
        string currentLine = lines[line0];
        size_t startPos = char0;
        while (startPos > 0 && wordChars.canFind(currentLine[startPos - 1]))
        {
            --startPos;
        }

        size_t nextPos = startPos + word.length;
        if (nextPos <= currentLine.length)
        {
            while (nextPos < currentLine.length && currentLine[nextPos] == ' ')
            {
                nextPos++;
            }
            while (nextPos < currentLine.length && currentLine[nextPos] == ' ')
            {
                ++nextPos;
            }
            if (nextPos < currentLine.length && currentLine[nextPos] == '(')
            {
                info.kind = SymbolKind.Function;
                info.context = "function call";
                bool found = false;
                foreach (idx, ln; lines)
                {
                    auto stripped = ln.strip();
                    if (stripped.startsWith("def " ~ word) || stripped.startsWith("pub def " ~ word))
                    {
                        info.doc = getDocStringAboveLine(lines, idx);
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    string defUri;
                    size_t outLine;
                    size_t outChar;
                    string currPath = uriToPath(currentUri);
                    if (findDefinitionAcrossFiles(currPath, word, defUri, outLine, outChar))
                    {
                        auto it2 = defUri in g_openDocs;
                        string defText;
                        if (it2 !is null)
                        {
                            defText = *it2;
                        }
                        else
                        {
                            try
                            {
                                defText = readText(uriToPath(defUri));
                            }
                            catch (Exception)
                            {
                                defText = "";
                            }
                        }
                        if (defText.length > 0)
                        {
                            auto defLines = defText.splitLines();
                            info.doc = getDocStringAboveLine(defLines, outLine);
                            found = true;
                        }
                    }
                }
                return info;
            }
        }

        auto defPattern = "def " ~ word;
        auto pubDefPattern = "pub def " ~ word;
        if (currentLine.strip().startsWith(defPattern) || currentLine.strip()
            .startsWith(pubDefPattern))
        {
            info.kind = SymbolKind.Function;
            info.context = "function definition";
            info.doc = getDocStringAboveLine(lines, line0);
            return info;
        }

        auto modelPattern = "model " ~ word;
        if (currentLine.strip().startsWith(modelPattern))
        {
            info.kind = SymbolKind.Model;
            info.context = "model definition";
            return info;
        }

        if (currentLine.canFind("val " ~ word) || currentLine.canFind("mut " ~ word))
        {
            info.kind = SymbolKind.Variable;
            info.context = "variable";
            return info;
        }

        if (char0 > 0 && currentLine[char0 - 1] == '.')
        {
            info.kind = SymbolKind.Property;
            info.context = "property or method";
            return info;
        }

        if (currentLine.canFind(word ~ ":"))
        {
            info.kind = SymbolKind.Variable;
            info.context = "parameter";
            return info;
        }

        if (word.length >= 2 && word[0] >= 'A' && word[0] <= 'Z' && word[1] >= 'a' && word[1] <= 'z')
        {
            info.kind = SymbolKind.Model;
            info.context = "type-like";
            return info;
        }
    }

    info.kind = SymbolKind.Variable;
    return info;
}

string getDocStringAboveLine(string[] lines, size_t defLine)
{
    if (defLine == 0)
        return "";
    string[] parts;
    long i = cast(long) defLine - 1;
    for (; i >= 0; --i)
    {
        auto trimmed = lines[i].strip();
        if (trimmed.length == 0)
        {
            continue;
        }
        if (trimmed.startsWith("///"))
        {
            parts ~= trimmed[3 .. $].strip();
            continue;
        }
        break;
    }
    if (parts.length == 0)
        return "";
    parts.reverse();
    return parts.join("\n");
}

/// Determine whether the position is inside a comment (line or block)
bool positionInStringOrComment(string text, size_t line0, size_t char0)
{
    auto lines = text.splitLines();
    bool inBlock = false;

    for (size_t ln = 0; ln <= line0 && ln < lines.length; ++ln)
    {
        auto line = lines[ln];
        size_t limit = (ln == line0) ? char0 : line.length;
        bool inLineComment = false;
        for (size_t j = 0; j < limit && j < line.length; ++j)
        {
            char c = line[j];
            if (inBlock)
            {
                if (c == '*' && j + 1 < line.length && line[j + 1] == '/')
                {
                    inBlock = false;
                    ++j;
                }
                continue;
            }
            if (inLineComment)
            {
                continue;
            }

            if (c == '/' && j + 1 < line.length)
            {
                char n = line[j + 1];
                if (n == '/')
                {
                    inLineComment = true;
                    if (ln == line0 && limit > j)
                    {
                        return true;
                    }
                    break;
                }
                else if (n == '*')
                {
                    inBlock = true;
                    ++j;
                    continue;
                }
            }
        }
        if (ln == line0)
        {
            if (inBlock || inLineComment)
                return true;
            return false;
        }
    }
    return false;
}

string getHoverText(SymbolInfo info)
{
    final switch (info.kind)
    {
    case SymbolKind.Keyword:
        return "**`" ~ info.name ~ "`** *(keyword)*\n\nAxe language keyword";
    case SymbolKind.Type:
        return "**`" ~ info.name ~ "`** *(type)*\n\nBuilt-in type";
    case SymbolKind.Function:
        {
            string header = "";
            if (info.doc.length > 0)
            {
                header = info.doc ~ "\n\n";
            }
            if (info.context == "function definition")
            {
                return header ~ "**`def " ~ info.name ~ "`** *(function)*\n\nFunction definition";
            }
            return header ~ "**`" ~ info.name ~ "()`** *(function)*\n\nFunction call";
        }
    case SymbolKind.Variable:
        if (info.context == "parameter")
        {
            return "**`" ~ info.name ~ "`** *(parameter)*\n\nFunction parameter";
        }
        return "**`" ~ info.name ~ "`** *(variable)*\n\nVariable";
    case SymbolKind.Builtin:
        return "**`" ~ info.name ~ "`** *(builtin)*\n\nBuilt-in function or type";
    case SymbolKind.Model:
        return "**`model " ~ info.name ~ "`** *(model)*\n\nModel definition or reference";
    case SymbolKind.Property:
        return "**`" ~ info.name ~ "`** *(property)*\n\nProperty or method access";
    case SymbolKind.Unknown:
        return "**`" ~ info.name ~ "`** *(symbol)*\n\nSymbol in Axe code";
    }
}

void handleHover(LspRequest req)
{
    debugLog("Handling hover request");

    auto params = req.params;
    if (params.type != JSONType.object)
    {
        debugLog("hover: params not an object");
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    auto pObj = params.object;
    if (!("textDocument" in pObj) || !("position" in pObj))
    {
        debugLog("hover: missing textDocument or position");
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    auto td = pObj["textDocument"].object;
    string uri = td["uri"].str;

    auto pos = pObj["position"].object;
    size_t line0 = cast(size_t) pos["line"].integer;
    size_t char0 = cast(size_t) pos["character"].integer;

    debugLog("hover: uri=", uri, ", line=", line0, ", char=", char0);

    auto it = uri in g_openDocs;
    if (it is null)
    {
        debugLog("hover: document not found in g_openDocs");
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    string text = *it;
    if (positionInStringOrComment(text, line0, char0))
    {
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }
    string word = extractWordAt(text, line0, char0);
    debugLog("hover: extracted word='", word, "'");

    if (word.length == 0)
    {
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    SymbolInfo symbolInfo = analyzeSymbol(word, text, line0, char0, uri);
    string hoverText = getHoverText(symbolInfo);

    JSONValue contents;
    contents["kind"] = "markdown";
    contents["value"] = hoverText;

    JSONValue result;
    result["contents"] = contents;

    sendResponse(req.id, result);
    debugLog("hover: response sent");
}

void handleCompletion(LspRequest req)
{
    debugLog("Handling completion request");

    auto params = req.params;
    if (params.type != JSONType.object)
    {
        debugLog("completion: params not an object");
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    auto pObj = params.object;
    if (!("textDocument" in pObj) || !("position" in pObj))
    {
        debugLog("completion: missing textDocument or position");
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    auto td = pObj["textDocument"].object;
    string uri = td["uri"].str;

    auto pos = pObj["position"].object;
    size_t line0 = cast(size_t) pos["line"].integer;
    size_t char0 = cast(size_t) pos["character"].integer;

    debugLog("completion: uri=", uri, ", line=", line0, ", char=", char0);

    auto it = uri in g_openDocs;
    if (it is null)
    {
        debugLog("completion: document not found");
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    string text = *it;

    auto lines = text.splitLines();
    bool isDotCompletion = false;
    string wordBeforeDot = "";

    if (line0 < lines.length && char0 > 0)
    {
        auto line = lines[line0];
        size_t checkPos = char0 - 1;
        while (checkPos > 0 && wordChars.canFind(line[checkPos]))
            checkPos--;

        if (checkPos < line.length && line[checkPos] == '.')
        {
            isDotCompletion = true;
            wordBeforeDot = extractWordBeforeDot(text, line0, checkPos + 1);
            debugLog("completion: dot completion triggered, word before dot='", wordBeforeDot, "'");
        }
        else if (char0 > 0 && char0 <= line.length && line[char0 - 1] == '.')
        {
            isDotCompletion = true;
            wordBeforeDot = extractWordBeforeDot(text, line0, char0);
            debugLog("completion: dot completion at cursor, word before dot='", wordBeforeDot, "'");
        }
    }

    JSONValue[] items;
    bool[string] seen;

    if (isDotCompletion && wordBeforeDot.length > 0)
    {
        debugLog("completion: handling dot completion for '", wordBeforeDot, "'");

        ModelDef[] allModels;

        auto docModels = parseModelsFromText(text);
        allModels ~= docModels;
        string currPath = uriToPath(uri);
        auto projectModels = loadProjectModels(currPath);

        foreach (pm; projectModels)
        {
            bool found = false;
            foreach (m; allModels)
            {
                if (m.name == pm.name)
                {
                    found = true;
                    break;
                }
            }
            if (!found)
                allModels ~= pm;
        }

        auto stdModels = loadStdLibModels();
        allModels ~= stdModels;

        debugLog("completion: loaded ", allModels.length, " total models");

        string targetModelName = "";
        foreach (model; allModels)
        {
            if (model.name == wordBeforeDot)
            {
                targetModelName = model.name;
                debugLog("completion: found direct model match '", model.name, "'");
                break;
            }
        }

        if (targetModelName.length == 0)
        {
            targetModelName = findVariableType(text, wordBeforeDot, line0, char0);
            debugLog("completion: variable '", wordBeforeDot, "' has type '", targetModelName, "'");
        }

        if (targetModelName.length > 0)
        {
            foreach (model; allModels)
            {
                if (model.name == targetModelName)
                {
                    debugLog("completion: providing completions for model '", model.name, "'");

                    foreach (field; model.fields)
                    {
                        if (field.name !in seen)
                        {
                            JSONValue item;
                            item["label"] = field.name;
                            item["kind"] = 5L;
                            item["detail"] = field.type;
                            if (field.doc.length > 0)
                            {
                                JSONValue docVal;
                                docVal["kind"] = "markdown";
                                docVal["value"] = field.doc;
                                item["documentation"] = docVal;
                            }
                            items ~= item;
                            seen[field.name] = true;
                        }
                    }
                    foreach (method; model.methods)
                    {
                        if (method.name !in seen)
                        {
                            JSONValue item;
                            item["label"] = method.name;
                            item["kind"] = 2L; // Method
                            item["detail"] = method.signature;
                            if (method.doc.length > 0)
                            {
                                JSONValue docVal;
                                docVal["kind"] = "markdown";
                                docVal["value"] = method.doc;
                                item["documentation"] = docVal;
                            }
                            item["insertText"] = method.name ~ "(";
                            items ~= item;
                            seen[method.name] = true;
                        }
                    }

                    break;
                }
            }
        }

        debugLog("completion: dot completion returning ", items.length, " items");

        JSONValue result;
        result["isIncomplete"] = false;
        result["items"] = JSONValue(items);
        sendResponse(req.id, result);
        return;
    }

    string prefix = extractWordAt(text, line0, char0);
    debugLog("completion: prefix='", prefix, "'");

    string[] keywords = [
        "def", "pub", "mut", "val", "loop", "for", "in", "if", "else",
        "elif", "switch", "case", "break", "continue", "model", "enum",
        "use", "test", "assert", "unsafe", "parallel", "single", "platform",
        "return"
    ];

    foreach (k; keywords)
    {
        if (prefix.length == 0 || k.startsWith(prefix))
        {
            if (k !in seen)
            {
                JSONValue item;
                item["label"] = k;
                item["kind"] = 14L; // Keyword
                item["detail"] = "keyword";
                items ~= item;
                seen[k] = true;
            }
        }
    }

    foreach (ln; text.splitLines())
    {
        string current;
        foreach (ch; ln)
        {
            if (wordChars.canFind(ch))
            {
                current ~= ch;
            }
            else
            {
                if (current.length > 0 && (prefix.length == 0 || current.startsWith(prefix)))
                {
                    if (current !in seen)
                    {
                        JSONValue item;
                        item["label"] = current;
                        item["kind"] = 6L; // Variable
                        items ~= item;
                        seen[current] = true;
                    }
                }
                current = "";
            }
        }
        if (current.length > 0 && (prefix.length == 0 || current.startsWith(prefix)))
        {
            if (current !in seen)
            {
                JSONValue item;
                item["label"] = current;
                item["kind"] = 6L;
                items ~= item;
                seen[current] = true;
            }
        }
    }

    // Also add model names from std lib for regular completion
    auto stdModels = loadStdLibModels();
    foreach (model; stdModels)
    {
        if (prefix.length == 0 || model.name.startsWith(prefix))
        {
            if (model.name !in seen)
            {
                JSONValue item;
                item["label"] = model.name;
                item["kind"] = 7L; // Class/Model
                item["detail"] = "model";
                if (model.doc.length > 0)
                {
                    JSONValue docVal;
                    docVal["kind"] = "markdown";
                    docVal["value"] = model.doc;
                    item["documentation"] = docVal;
                }
                items ~= item;
                seen[model.name] = true;
            }
        }
    }

    debugLog("completion: returning ", items.length, " items");

    JSONValue result;
    result["isIncomplete"] = false;
    result["items"] = JSONValue(items);

    sendResponse(req.id, result);
}

/// Handle documentSymbol request
void handleDocumentSymbol(LspRequest req)
{
    debugLog("Handling documentSymbol request");

    auto params = req.params;
    if (params.type != JSONType.object)
    {
        debugLog("documentSymbol: params not an object");
        JSONValue[] emptyArr;
        sendResponse(req.id, JSONValue(emptyArr));
        return;
    }

    auto pObj = params.object;
    if (!("textDocument" in pObj))
    {
        debugLog("documentSymbol: missing textDocument");
        JSONValue[] emptyArr;
        sendResponse(req.id, JSONValue(emptyArr));
        return;
    }

    auto td = pObj["textDocument"].object;
    string uri = td["uri"].str;

    auto it = uri in g_openDocs;
    string text;
    if (it is null)
    {
        try
        {
            text = readText(uriToPath(uri));
        }
        catch (Exception)
        {
            JSONValue[] emptyArr;
            sendResponse(req.id, JSONValue(emptyArr));
            return;
        }
    }
    else
    {
        text = *it;
    }

    JSONValue[] results;

    auto lines = text.splitLines();
    foreach (idx, ln; lines)
    {
        auto t = ln.strip();
        if (t.length == 0)
            continue;

        if (t.startsWith("def ") || t.startsWith("pub def "))
        {
            string name;
            size_t pos;
            if (auto p = ln.indexOf("def") >= 0)
            {
                pos = cast(size_t) ln.indexOf("def");
                size_t start = pos + 3;
                while (start < ln.length && ln[start] == ' ')
                    ++start;
                size_t end = start;
                while (end < ln.length && wordChars.canFind(ln[end]))
                    ++end;
                name = ln[start .. end];

                JSONValue symbol;
                symbol["name"] = name.length > 0 ? name : t;
                symbol["kind"] = 12L;

                JSONValue range;
                JSONValue sPos;
                JSONValue ePos;
                sPos["line"] = cast(long) idx;
                sPos["character"] = cast(long) pos;
                ePos["line"] = cast(long) idx;
                ePos["character"] = cast(long)(pos + name.length);
                range["start"] = sPos;
                range["end"] = ePos;

                symbol["range"] = range;
                symbol["selectionRange"] = range;

                results ~= symbol;
            }
        }

        else if (t.startsWith("model "))
        {
            size_t pos = cast(size_t) ln.indexOf("model");
            size_t start = pos + 5;
            while (start < ln.length && ln[start] == ' ')
                ++start;
            size_t end = start;
            while (end < ln.length && wordChars.canFind(ln[end]))
                ++end;
            string name = ln[start .. end];

            JSONValue symbol;
            symbol["name"] = name.length > 0 ? name : t;
            symbol["kind"] = 5L;

            JSONValue range;
            JSONValue sPos;
            JSONValue ePos;
            sPos["line"] = cast(long) idx;
            sPos["character"] = cast(long) pos;
            ePos["line"] = cast(long) idx;
            ePos["character"] = cast(long)(pos + name.length);
            range["start"] = sPos;
            range["end"] = ePos;

            symbol["range"] = range;
            symbol["selectionRange"] = range;

            results ~= symbol;
        }

        else if (t.startsWith("enum "))
        {
            size_t pos = cast(size_t) ln.indexOf("enum");
            size_t start = pos + 4;
            while (start < ln.length && ln[start] == ' ')
                ++start;
            size_t end = start;
            while (end < ln.length && wordChars.canFind(ln[end]))
                ++end;
            string name = ln[start .. end];

            JSONValue symbol;
            symbol["name"] = name.length > 0 ? name : t;
            symbol["kind"] = 10L; // Enum

            JSONValue range;
            JSONValue sPos;
            JSONValue ePos;
            sPos["line"] = cast(long) idx;
            sPos["character"] = cast(long) pos;
            ePos["line"] = cast(long) idx;
            ePos["character"] = cast(long)(pos + name.length);
            range["start"] = sPos;
            range["end"] = ePos;

            symbol["range"] = range;
            symbol["selectionRange"] = range;

            results ~= symbol;
        }

        else if (t.startsWith("val ") || t.startsWith("mut "))
        {
            size_t pos = 0;
            if (auto p = ln.indexOf("val") >= 0)
                pos = cast(size_t) ln.indexOf("val");
            else if (auto p2 = ln.indexOf("mut") >= 0)
                pos = cast(size_t) ln.indexOf("mut");

            size_t start = pos;
            string name;
            size_t after = pos;
            if (ln.canFind("val "))
                after = cast(size_t) ln.indexOf("val") + 3;
            else if (ln.canFind("mut "))
                after = cast(size_t) ln.indexOf("mut") + 3;
            while (after < ln.length && ln[after] == ' ')
                ++after;
            size_t end = after;
            while (end < ln.length && wordChars.canFind(ln[end]))
                ++end;
            name = ln[after .. end];

            if (name.length > 0)
            {
                JSONValue symbol;
                symbol["name"] = name;
                symbol["kind"] = 13L;
                JSONValue range;
                JSONValue sPos;
                JSONValue ePos;
                sPos["line"] = cast(long) idx;
                sPos["character"] = cast(long) pos;
                ePos["line"] = cast(long) idx;
                ePos["character"] = cast(long)(pos + name.length);
                range["start"] = sPos;
                range["end"] = ePos;

                symbol["range"] = range;
                symbol["selectionRange"] = range;

                results ~= symbol;
            }
        }
    }

    sendResponse(req.id, JSONValue(results));
    debugLog("documentSymbol: returned ", results.length, " symbols for ", uri);
}

/// Search for a function definition for `word` inside a single file's text
bool findDefinitionInText(string text, string word, out size_t foundLine, out size_t foundChar)
{
    auto lines = text.splitLines();
    string pat1 = "def " ~ word;
    string pat2 = "pub def " ~ word;
    string pat3 = "model " ~ word;
    string pat4 = "pub model " ~ word;
    string pat5 = "enum " ~ word;
    string pat6 = "pub enum " ~ word;

    foreach (idx, ln; lines)
    {
        auto t = ln.strip();
        if (t.startsWith(pat1) || t.startsWith(pat2))
        {
            auto pos = ln.indexOf("def");
            if (pos < 0)
                pos = 0;
            foundLine = idx;
            foundChar = cast(size_t) pos;
            return true;
        }
        if (t.startsWith(pat3) || t.startsWith(pat4))
        {
            auto pos = ln.indexOf("model");
            if (pos < 0)
                pos = 0;
            foundLine = idx;
            foundChar = cast(size_t) pos;
            return true;
        }
        if (t.startsWith(pat5) || t.startsWith(pat6))
        {
            auto pos = ln.indexOf("enum");
            if (pos < 0)
                pos = 0;
            foundLine = idx;
            foundChar = cast(size_t) pos;
            return true;
        }
    }
    return false;
}

/// Try to find definition across open documents and on-disk files (searching from file's directory)
bool findDefinitionAcrossFiles(
    string currentPath,
    string word,
    out string outUri,
    out size_t outLine,
    out size_t outChar
)
{
    foreach (uri, txt; g_openDocs)
    {
        size_t ln, ch;
        if (findDefinitionInText(txt, word, ln, ch))
        {
            outUri = uri;
            outLine = ln;
            outChar = ch;
            return true;
        }
    }

    string[] searchDirs = getSearchDirectories(currentPath);

    import std.file : dirEntries;
    import std.file : SpanMode;

    foreach (dir; searchDirs)
    {
        try
        {
            foreach (dirEntry; dirEntries(dir, SpanMode.depth))
            {
                if (!dirEntry.isFile)
                    continue;
                auto ext = dirEntry.name.split('.');
                if (ext.length == 0)
                    continue;
                auto fileExt = "." ~ ext[$ - 1];
                if (fileExt != ".axe" && fileExt != ".axec")
                    continue;

                string fileText;
                try
                {
                    fileText = readText(dirEntry.name);
                }
                catch (Exception)
                {
                    continue;
                }

                size_t ln, ch;
                if (findDefinitionInText(fileText, word, ln, ch))
                {
                    string fileUri = dirEntry.name;

                    version (Windows)
                    {
                        import std.array : replace;

                        fileUri = fileUri.replace("\\", "/");
                    }

                    if (!fileUri.startsWith("file://"))
                    {
                        if (!fileUri.startsWith("/"))
                            fileUri = "/" ~ fileUri;
                        fileUri = "file://" ~ fileUri;
                    }
                    outUri = fileUri;
                    outLine = ln;
                    outChar = ch;
                    return true;
                }
            }
        }
        catch (Exception)
        {
            continue;
        }
    }

    return false;
}

void handleDefinition(LspRequest req)
{
    debugLog("Handling definition request");

    auto params = req.params;
    if (params.type != JSONType.object)
    {
        debugLog("definition: params not an object");
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    auto pObj = params.object;
    if (!("textDocument" in pObj) || !("position" in pObj))
    {
        debugLog("definition: missing textDocument or position");
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    auto td = pObj["textDocument"].object;
    string uri = td["uri"].str;

    auto pos = pObj["position"].object;
    size_t line0 = cast(size_t) pos["line"].integer;
    size_t char0 = cast(size_t) pos["character"].integer;

    debugLog("definition: uri=", uri, ", line=", line0, ", char=", char0);

    auto it = uri in g_openDocs;
    if (it is null)
    {
        debugLog("definition: document not found in g_openDocs");
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    string text = *it;

    if (positionInStringOrComment(text, line0, char0))
    {
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    string word = extractWordAt(text, line0, char0);
    if (word.length == 0)
    {
        JSONValue empty;
        sendResponse(req.id, empty);
        return;
    }

    size_t defLine, defChar;
    if (findDefinitionInText(text, word, defLine, defChar))
    {
        JSONValue loc;
        loc["uri"] = uri;
        JSONValue range;
        JSONValue sPos;
        JSONValue ePos;
        sPos["line"] = cast(long) defLine;
        sPos["character"] = cast(long) defChar;
        ePos["line"] = cast(long) defLine;
        ePos["character"] = cast(long)(defChar + word.length);
        range["start"] = sPos;
        range["end"] = ePos;
        loc["range"] = range;

        JSONValue[] arr;
        arr ~= loc;
        JSONValue result = JSONValue(arr);
        sendResponse(req.id, result);
        return;
    }

    string defUri;
    size_t outLine, outChar;
    string currPath = uriToPath(uri);
    if (findDefinitionAcrossFiles(currPath, word, defUri, outLine, outChar))
    {
        JSONValue loc;
        loc["uri"] = defUri;
        JSONValue range;
        JSONValue sPos;
        JSONValue ePos;
        sPos["line"] = cast(long) outLine;
        sPos["character"] = cast(long) outChar;
        ePos["line"] = cast(long) outLine;
        ePos["character"] = cast(long)(outChar + word.length);
        range["start"] = sPos;
        range["end"] = ePos;
        loc["range"] = range;

        JSONValue[] arr;
        arr ~= loc;
        JSONValue result = JSONValue(arr);
        sendResponse(req.id, result);
        return;
    }

    JSONValue empty;
    sendResponse(req.id, empty);
}

void dispatch(LspRequest req)
{
    debugLog("Dispatching method: ", req.method);

    switch (req.method)
    {
    case "initialize":
        handleInitialize(req);
        break;
    case "initialized":
        handleInitialized(req);
        break;
    case "shutdown":
        handleShutdown(req);
        break;
    case "exit":
        handleExit(req);
        break;
    case "textDocument/didOpen":
        handleDidOpen(req);
        break;
    case "textDocument/didChange":
        handleDidChange(req);
        break;
    case "textDocument/didSave":
        handleDidSave(req);
        break;
    case "textDocument/didClose":
        handleDidClose(req);
        break;
    case "textDocument/hover":
        handleHover(req);
        break;
    case "textDocument/definition":
        handleDefinition(req);
        break;
    case "textDocument/completion":
        handleCompletion(req);
        break;
    case "textDocument/documentSymbol":
        handleDocumentSymbol(req);
        break;
    default:
        debugLog("Unknown method: ", req.method);
        if (req.id.type != JSONType.null_)
        {
            sendError(req.id, -32_601, "Method not found");
        }
        break;
    }
}

int main(string[] args)
{
    import std.process : environment;
    import std.stdio : stdin, stdout, stderr;

    version (Windows)
    {
        import core.stdc.stdio : _setmode, _O_BINARY;
        import core.stdc.stdio : fileno;

        _setmode(fileno(stdin.getFP()), _O_BINARY);
        _setmode(fileno(stdout.getFP()), _O_BINARY);
    }

    for (size_t i = 1; i < args.length; i++)
    {
        if (args[i] == "--stdlib" && i + 1 < args.length)
        {
            g_stdlibPath = args[i + 1];
            i++;
        }
    }

    if (environment.get("AXELS_DEBUG", "") == "1")
    {
        g_debugMode = true;
        debugLog("=== Axe Language Server Starting (Debug Mode) ===");
        if (g_stdlibPath.length > 0)
        {
            debugLog("Using stdlib path from argument: ", g_stdlibPath);
        }
        else
        {
            debugLog("Using default stdlib path: ", getStdLibPath());
        }
    }

    debugLog("Entering main loop");

    int messageCount = 0;
    while (true)
    {
        messageCount++;
        debugLog("Waiting for message #", messageCount, "...");
        stderr.flush();

        auto body = readMessage();
        if (body is null)
        {
            debugLog("Received null message, exiting");
            break;
        }

        debugLog("Processing message #", messageCount);

        try
        {
            auto req = parseRequest(body);
            if (req.method.length == 0)
            {
                debugLog("Empty method in request");
                continue;
            }
            dispatch(req);
        }
        catch (Exception e)
        {
            debugLog("Exception in main loop: ", e.msg);
            stderr.writeln("[ERROR] ", e);
            stderr.flush();
        }

        debugLog("Finished processing message #", messageCount);
        stderr.flush();
    }

    debugLog("Main loop exited");
    return 0;
}
