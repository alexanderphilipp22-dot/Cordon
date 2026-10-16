using System.Text;
using Cordon.Core;
using Cordon.Core.Model;
using Cordon.Core.Protocol;
using Cordon.Core.Security;
using Cordon.Gateway.McpFilter;
using Cordon.Gateway.Vault;

namespace Cordon.Gateway.Tests;

/// <summary>
/// Abhaengigkeitsfreier Selbsttest fuer die drei Enterprise-Module:
/// CodeInspector (Cordon.Core.Security), CredentialVault (Cordon.Gateway.Vault)
/// und McpToolFilter (Cordon.Gateway.McpFilter).
/// </summary>
internal static class Program
{
    private static int _failures;
    private static int _total;

    private static int Main()
    {
        Console.WriteLine("Cordon.Gateway.Tests");
        Console.WriteLine();

        RunCodeInspectorTests();
        RunVaultTests();
        RunMcpFilterTests();

        Console.WriteLine();
        Console.WriteLine($"{_total - _failures}/{_total} Tests bestanden.");

        if (_failures == 0)
        {
            Console.WriteLine("OK");
            return 0;
        }

        Console.Error.WriteLine($"{_failures} Test(s) FEHLGESCHLAGEN.");
        return 1;
    }

    // =====================================================================
    // CodeInspector (Cordon.Core.Security)
    // =====================================================================

    private static void RunCodeInspectorTests()
    {
        Section("CodeInspector — Python");

        Check("rohes socket-Import wird erkannt", () =>
            !InspectPython("import socket\n").IsAllowed);

        Check("from socket import wird erkannt", () =>
            !InspectPython("from socket import create_connection\n").IsAllowed);

        Check("ctypes wird erkannt", () =>
            !InspectPython("import ctypes\nlibc = ctypes.CDLL('libc.so')\n").IsAllowed);

        Check("subprocess wird erkannt", () =>
            !InspectPython("import subprocess\nsubprocess.run(['ls'])\n").IsAllowed);

        Check("os.system wird erkannt", () =>
            !InspectPython("os.system('rm -rf /')\n").IsAllowed);

        Check("winreg wird erkannt", () =>
            !InspectPython("import winreg\nwinreg.SetValueEx(...)\n").IsAllowed);

        Check("eval wird erkannt", () =>
            !InspectPython("eval(user_input)\n").IsAllowed);

        Check("pickle.loads wird erkannt", () =>
            !InspectPython("pickle.loads(payload)\n").IsAllowed);

        Check("__import__ umgeht die Pruefung nicht", () =>
            !InspectPython("s = __import__('socket')\n").IsAllowed);

        Check("importlib.import_module wird erkannt", () =>
            !InspectPython("importlib.import_module('os')\n").IsAllowed);

        Check("harmloser Python-Code passiert", () =>
            InspectPython("import json\nprint(json.dumps({'a': 1}))\n").IsAllowed);

        Check("leere Payload passiert", () =>
            InspectPython(string.Empty).IsAllowed);

        Section("CodeInspector — JavaScript");

        Check("child_process wird erkannt", () =>
            !InspectJavaScript("const { exec } = require('child_process');\n").IsAllowed);

        Check("net (raw socket) wird erkannt", () =>
            !InspectJavaScript("const net = require('net');\n").IsAllowed);

        Check("eval wird erkannt", () =>
            !InspectJavaScript("eval('alert(1)')\n").IsAllowed);

        Check("Function-Konstruktor wird erkannt", () =>
            !InspectJavaScript("const f = new Function('a', 'return a');\n").IsAllowed);

        Check("harmloser JS-Code passiert", () =>
            InspectJavaScript("console.log('hello')\nconst x = 1 + 1;\n").IsAllowed);

        Check("Finding traegt Zeilennummer", () =>
        {
            var result = InspectPython("print('a')\nimport ctypes\n");
            return !result.IsAllowed
                && result.Findings.Count == 1
                && result.Findings[0].Line == 2
                && result.Findings[0].RuleId == "python_ctypes";
        });
    }

    // =====================================================================
    // CredentialVault (Cordon.Gateway.Vault)
    // =====================================================================

    private static void RunVaultTests()
    {
        Section("CredentialVault");

        Check("Register + exakte Aufloesung", () =>
        {
            var vault = new CredentialVault();
            vault.Register("api.github.com", "Authorization", "Bearer gh_token");
            return vault.TryResolve("api.github.com", out var secret)
                && secret is not null
                && secret.HeaderName == "Authorization"
                && secret.HeaderValue == "Bearer gh_token";
        });

        Check("Domänen-Vergleich ist case-insensitiv", () =>
        {
            var vault = new CredentialVault();
            vault.Register("api.github.com", "Authorization", "x");
            return vault.TryResolve("API.GITHUB.COM", out _);
        });

        Check("Trailing-Dot und Grossschreibung werden normalisiert", () =>
        {
            var vault = new CredentialVault();
            vault.Register("API.OPENAI.COM.", "Authorization", "x");
            return vault.TryResolve("api.openai.com", out _);
        });

        Check("Kein Treffer fuer unbekannte Domäne", () =>
        {
            var vault = new CredentialVault();
            vault.Register("api.github.com", "Authorization", "x");
            return !vault.TryResolve("evil.com", out _);
        });

        Check("Kein Treffer fuer Teilstring-/Subdomänen-Missbrauch", () =>
        {
            var vault = new CredentialVault();
            vault.Register("github.com", "Authorization", "x");
            // "evilgithub.com" darf NICHT matchen (exakter Vergleich).
            return !vault.TryResolve("evilgithub.com", out _);
        });

        Check("Injektion setzt Header", () =>
        {
            var vault = new CredentialVault();
            vault.Register("api.github.com", "Authorization", "Bearer gh");
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var injected = VaultHeaderInjector.TryInject(headers, "api.github.com", vault);
            return injected && headers["Authorization"] == "Bearer gh";
        });

        Check("Injektion ueberschreibt Agenten-Header", () =>
        {
            var vault = new CredentialVault();
            vault.Register("api.github.com", "Authorization", "Bearer echtes-token");
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Authorization"] = "Bearer agent-eigenes-token",
            };
            _ = VaultHeaderInjector.TryInject(headers, "api.github.com", vault);
            return headers["Authorization"] == "Bearer echtes-token";
        });

        Check("Keine Injektion ohne Treffer", () =>
        {
            var vault = new CredentialVault();
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var injected = VaultHeaderInjector.TryInject(headers, "example.com", vault);
            return !injected && headers.Count == 0;
        });

        Check("Ungueltige Registrierung wirft", () =>
        {
            var vault = new CredentialVault();
            try
            {
                vault.Register("", "Authorization", "x");
                return false;
            }
            catch (ArgumentException)
            {
                return true;
            }
        });

        Check("CRLF im Header-Wert wird abgelehnt", () =>
        {
            var vault = new CredentialVault();
            try
            {
                vault.Register("api.github.com", "Authorization", "Bearer x\r\nX-Evil: 1");
                return false;
            }
            catch (ArgumentException)
            {
                return true;
            }
        });

        Check("Doppelpunkt im Header-Namen wird abgelehnt", () =>
        {
            var vault = new CredentialVault();
            try
            {
                vault.Register("api.github.com", "X-Evil: yes", "v");
                return false;
            }
            catch (ArgumentException)
            {
                return true;
            }
        });

        Check("ToString gibt Geheimnis nicht preis", () =>
        {
            var secret = new VaultSecret("api.github.com", "Authorization", "super-secret");
            return !secret.ToString().Contains("super-secret", StringComparison.Ordinal);
        });
    }

    // =====================================================================
    // McpToolFilter (Cordon.Gateway.McpFilter)
    // =====================================================================

    private static void RunMcpFilterTests()
    {
        Section("McpToolFilter");

        var policy = new McpToolPolicy(["read_file", "search_code", "list_files"]);

        Check("JSON-RPC-Toolaufruf wird erkannt und erlaubt", () =>
        {
            var d = McpToolFilter.Inspect(
                J("""{"method":"tools/call","params":{"name":"read_file"}}"""),
                policy);
            return d.Allowed && d.ToolName == "read_file";
        });

        Check("Gefaehrliches Tool wird abgelehnt", () =>
        {
            var d = McpToolFilter.Inspect(
                J("""{"method":"tools/call","params":{"name":"delete_database"}}"""),
                policy);
            return !d.Allowed && d.Code == DenyCodes.ToolNotAllowed;
        });

        Check("Direkte Tool-Form wird erkannt", () =>
        {
            var d = McpToolFilter.Inspect(J("""{"tool":"search_code"}"""), policy);
            return d.Allowed && d.ToolName == "search_code";
        });

        Check("Direkte name-Form wird erkannt", () =>
        {
            var d = McpToolFilter.Inspect(J("""{"name":"list_files"}"""), policy);
            return d.Allowed;
        });

        Check("Malformed JSON wird fail-closed abgelehnt", () =>
        {
            var d = McpToolFilter.Inspect(J("{nicht-json"), policy);
            return !d.Allowed && d.Code == DenyCodes.ProtocolError;
        });

        Check("Tief verschachteltes JSON wird sauber abgelehnt", () =>
        {
            var deep = new string('[', 100) + "1" + new string(']', 100);
            var d = McpToolFilter.Inspect(J(deep), policy);
            return !d.Allowed && d.Code == DenyCodes.ProtocolError;
        });

        Check("Widerspruechliche Toolnamen werden abgelehnt", () =>
        {
            var d = McpToolFilter.Inspect(
                J("""{"name":"read_file","tool":"delete_database"}"""),
                policy);
            return !d.Allowed && d.Code == DenyCodes.ProtocolError;
        });

        Check("Fehlender Toolname wird abgelehnt", () =>
        {
            var d = McpToolFilter.Inspect(J("""{"params":{}}"""), policy);
            return !d.Allowed && d.Code == DenyCodes.MalformedTarget;
        });

        Check("Leere Whitelist lehnt alles ab", () =>
        {
            var empty = new McpToolPolicy([]);
            var d = McpToolFilter.Inspect(J("""{"tool":"read_file"}"""), empty);
            return !d.Allowed && d.Code == DenyCodes.ToolNotAllowed;
        });

        Check("Authorize wirft strukturierte Exception", () =>
        {
            try
            {
                McpToolFilter.Authorize(J("""{"tool":"git_push"}"""), policy);
                return false;
            }
            catch (CordonProtocolException ex)
            {
                return ex.Code == DenyCodes.ToolNotAllowed;
            }
        });

        Check("Authorize wirft nicht bei erlaubtem Tool", () =>
        {
            try
            {
                McpToolFilter.Authorize(J("""{"tool":"read_file"}"""), policy);
                return true;
            }
            catch (CordonProtocolException)
            {
                return false;
            }
        });

        Check("FromScope baut Whitelist aus Scope", () =>
        {
            var scope = new ScopeGrant
            {
                Id = "s",
                Principals = new ScopePrincipal { AgentIds = ["a"] },
                Targets = [new ScopeTarget { Host = "api.example.com", Ports = [443] }],
                AllowedTools = ["read_file"],
            };
            var fromScope = McpToolPolicy.FromScope(scope);
            return fromScope.Allows("read_file") && !fromScope.Allows("git_push");
        });
    }

    // =====================================================================
    // Helfer
    // =====================================================================

    private static CodeInspectionResult InspectPython(string source) =>
        CodeInspector.Inspect(source, CodeInspector.DefaultPythonRules);

    private static CodeInspectionResult InspectJavaScript(string source) =>
        CodeInspector.Inspect(source, CodeInspector.DefaultJavaScriptRules);

    private static byte[] J(string json) => Encoding.UTF8.GetBytes(json);

    private static void Section(string name)
    {
        Console.WriteLine($"--- {name} ---");
    }

    private static void Check(string name, Func<bool> assertion)
    {
        _total++;

        bool passed;
        string? error = null;

        try
        {
            passed = assertion();
        }
        catch (Exception ex)
        {
            passed = false;
            error = $"{ex.GetType().Name}: {ex.Message}";
        }

        if (passed)
        {
            Console.WriteLine($"  ok   {name}");
        }
        else
        {
            _failures++;
            Console.Error.WriteLine($"  FAIL {name}{(error is null ? string.Empty : $" ({error})")}");
        }
    }
}
