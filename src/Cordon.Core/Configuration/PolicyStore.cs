using System.Text.Json;
using Cordon.Core.Model;
using Cordon.Core.Policy;

namespace Cordon.Core.Configuration;

/// <summary>
/// Verwaltet das Laden, Validieren und optionale Ueberwachen der Policy-Datei.
/// </summary>
public sealed class PolicyStore : IDisposable
{
    private readonly string _path;
    private readonly bool _watch;
    private readonly object _syncLock = new();
    private FileSystemWatcher? _watcher;
    private CompiledPolicy? _current;
    private IReadOnlyList<string> _lastErrors = [];
    private bool _disposed;

    /// <summary>
    /// Wird ausgeloest, wenn eine geaenderte Policy neu geladen wurde.
    /// Bei Misserfolg bleibt die zuletzt gueltige Policy aktiv.
    /// </summary>
    public event Action<bool, IReadOnlyList<string>>? Reloaded;

    public PolicyStore(string path, bool watch = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = System.IO.Path.GetFullPath(path);
        _watch = watch;

        if (_watch)
        {
            SetupWatcher();
        }
    }

    public string Path => _path;

    /// <summary>Die aktuell gueltige kompilierte Policy oder <c>null</c>.</summary>
    public CompiledPolicy? Current
    {
        get
        {
            lock (_syncLock)
            {
                return _current;
            }
        }
    }

    /// <summary>Fehlermeldungen des letzten Ladeversuchs.</summary>
    public IReadOnlyList<string> LastErrors
    {
        get
        {
            lock (_syncLock)
            {
                return _lastErrors;
            }
        }
    }

    /// <summary>
    /// Laedt die Policy synchron. Gibt <c>true</c> zurueck, wenn das Laden
    /// und Kompilieren erfolgreich war.
    /// </summary>
    public bool Load()
    {
        lock (_syncLock)
        {
            var (success, errors, policy) = LoadCore();
            _lastErrors = errors;
            if (success && policy is not null)
            {
                _current = policy;
            }

            return success;
        }
    }

    private (bool Success, IReadOnlyList<string> Errors, CompiledPolicy? Policy) LoadCore()
    {
        if (!File.Exists(_path))
        {
            return (false, [$"Policy-Datei '{_path}' existiert nicht."], null);
        }

        ScopeConfiguration? config = null;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                var json = File.ReadAllBytes(_path);
                config = JsonSerializer.Deserialize(json, CordonJsonContext.Default.ScopeConfiguration);
                if (config is null)
                {
                    return (false, ["Policy-Datei ist leer oder enthaelt kein gueltiges ScopeConfiguration-Objekt."], null);
                }

                break;
            }
            catch (IOException) when (attempt < 2)
            {
                Thread.Sleep(50);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                return (false, [$"Fehler beim Lesen der Policy-Datei: {ex.Message}"], null);
            }
        }

        if (config is null)
        {
            return (false, ["Policy-Datei konnte nicht gelesen werden."], null);
        }

        try
        {
            var result = PolicyEngine.Compile(config);
            if (!result.Success || result.Policy is null)
            {
                return (false, result.Errors, null);
            }

            return (true, [], result.Policy);
        }
        catch (Exception ex)
        {
            // Ein unerwarteter Kompilierfehler darf niemals als unbehandelte
            // Exception bis in den FileSystemWatcher-Callback wandern (der den
            // Prozess beenden wuerde). Fail closed: die zuletzt gueltige Policy
            // bleibt aktiv.
            return (false, [$"Policy-Kompilierung fehlgeschlagen: {ex.Message}"], null);
        }
    }

    private void SetupWatcher()
    {
        var dir = System.IO.Path.GetDirectoryName(_path);
        if (string.IsNullOrEmpty(dir))
        {
            dir = Directory.GetCurrentDirectory();
        }

        if (!Directory.Exists(dir))
        {
            return;
        }

        var fileName = System.IO.Path.GetFileName(_path);
        _watcher = new FileSystemWatcher(dir, fileName)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime,
            EnableRaisingEvents = true,
        };

        _watcher.Changed += OnFileChanged;
        _watcher.Created += OnFileChanged;
        _watcher.Renamed += OnFileRenamed;
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        TriggerReload();
    }

    private void OnFileRenamed(object sender, RenamedEventArgs e)
    {
        TriggerReload();
    }

    private void TriggerReload()
    {
        Thread.Sleep(50);

        bool success;
        IReadOnlyList<string> errors;

        lock (_syncLock)
        {
            if (_disposed)
            {
                return;
            }

            var (s, errs, policy) = LoadCore();
            success = s;
            errors = errs;
            _lastErrors = errs;
            if (success && policy is not null)
            {
                _current = policy;
            }
        }

        try
        {
            Reloaded?.Invoke(success, errors);
        }
        catch
        {
            // Ein werfender Abonnent (z. B. eine fehlschlagende SID-Aufloesung
            // beim Listener-Sync) darf den FileSystemWatcher-Thread und damit
            // den gesamten Prozess nicht zum Absturz bringen. Der Ladezustand
            // ist bereits konsistent gesetzt.
        }
    }

    public void Dispose()
    {
        lock (_syncLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _watcher?.Dispose();
            _watcher = null;
        }
    }
}