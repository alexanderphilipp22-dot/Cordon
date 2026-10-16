using System.Collections.Concurrent;

namespace Cordon.Gateway;

/// <summary>
/// Erzwingt <c>maxConcurrentConnections</c> pro Scope ueber alle Agenten und
/// Pipe-Verbindungen hinweg.
/// <para>
/// Der Zaehler wird mit Compare-And-Swap gefuehrt, damit die Grenze auf dem
/// heissen Pfad ohne grobe Sperre gilt. Ein Scope, dessen Zaehler auf 0 faellt,
/// wird aus der Map entfernt, damit kein unbegrenztes Wachstum entsteht.
/// </para>
/// </summary>
internal sealed class ScopeConnectionLimiter
{
    private readonly ConcurrentDictionary<string, int> _active = new(StringComparer.Ordinal);

    /// <summary>
    /// Reserviert einen Verbindungsplatz fuer einen Scope.
    /// Gibt <c>false</c> zurueck, wenn die Grenze erreicht oder ungueltig ist.
    /// </summary>
    public bool TryAcquire(string scopeId, int max)
    {
        if (string.IsNullOrEmpty(scopeId) || max <= 0)
        {
            return false;
        }

        while (true)
        {
            var current = _active.GetOrAdd(scopeId, 0);
            if (current >= max)
            {
                return false;
            }

            if (_active.TryUpdate(scopeId, current + 1, current))
            {
                return true;
            }
        }
    }

    /// <summary>Gibt einen zuvor reservierten Platz wieder frei.</summary>
    public void Release(string scopeId)
    {
        if (string.IsNullOrEmpty(scopeId))
        {
            return;
        }

        while (true)
        {
            if (!_active.TryGetValue(scopeId, out var current))
            {
                return;
            }

            if (current <= 1)
            {
                _active.TryRemove(scopeId, out _);
                return;
            }

            if (_active.TryUpdate(scopeId, current - 1, current))
            {
                return;
            }
        }
    }
}
