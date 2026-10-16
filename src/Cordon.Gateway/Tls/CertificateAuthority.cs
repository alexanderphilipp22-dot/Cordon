using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cordon.Gateway.Tls;

/// <summary>
/// Lokale CA und Leaf-Ausstellung fuer die <b>optionale</b>
/// TLS-Interception.
/// <para>
/// <b>Entscheidende Eigenschaft:</b> Die CA wird <b>niemals</b> in den
/// Windows-Zertifikatsspeicher geschrieben. Sie wird ausschliesslich dem
/// Agenten uebergeben, der Interception ausdruecklich angefordert hat.
/// Damit gewinnt kein anderer Prozess auf dem Host zusaetzliches Vertrauen -
/// anders als bei einer systemweit installierten MITM-CA, die zum
/// Angriffsziel fuer jeden lokalen Prozess wird.
/// </para>
/// <para>
/// Der private Schluessel liegt in <c>%ProgramData%\Cordon\ca</c> und ist
/// per ACL gegen Zugriff durch Agenten zu schuetzen (siehe <c>cordon init</c>).
/// </para>
/// </summary>
public sealed class CertificateAuthority : IDisposable
{
    private readonly X509Certificate2 _caCertificate;
    private readonly ConcurrentDictionary<string, X509Certificate2> _leafCache = new(StringComparer.Ordinal);
    private readonly TimeSpan _leafLifetime;

    private CertificateAuthority(X509Certificate2 caCertificate, TimeSpan leafLifetime)
    {
        _caCertificate = caCertificate;
        _leafLifetime = leafLifetime;
    }

    /// <summary>Das CA-Zertifikat (oeffentlicher Teil) fuer die Agenten-Kette.</summary>
    public X509Certificate2 Certificate => _caCertificate;

    public string Subject => _caCertificate.Subject;

    /// <summary>Erzeugt eine neue CA oder laedt eine vorhandene aus dem Verzeichnis.</summary>
    public static CertificateAuthority LoadOrCreate(
        string directory,
        string commonName = "Cordon Local Inspection CA",
        TimeSpan? leafLifetime = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        Directory.CreateDirectory(directory);

        var certificatePath = Path.Combine(directory, "cordon-ca.pfx");
        var passwordPath = Path.Combine(directory, "cordon-ca.pwd");

        if (File.Exists(certificatePath) && File.Exists(passwordPath))
        {
            var password = File.ReadAllText(passwordPath).Trim();
            var existing = new X509Certificate2(
                certificatePath,
                password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);

            if (existing.NotAfter > DateTime.Now.AddDays(30) && existing.HasPrivateKey)
            {
                return new CertificateAuthority(existing, leafLifetime ?? TimeSpan.FromDays(90));
            }

            existing.Dispose();
        }

        var created = CreateRoot(commonName);

        // Passwort zufaellig und dateibasiert: der Schluessel soll nicht
        // ohne Dateizugriff verwendbar sein. Der Schutz kommt primaer von
        // der Verzeichnis-ACL, nicht von diesem Passwort - es verhindert
        // versehentliche Nutzung, nicht einen entschlossenen Angreifer.
        var generatedPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        File.WriteAllBytes(
            certificatePath,
            created.Export(X509ContentType.Pkcs12, generatedPassword));
        File.WriteAllText(passwordPath, generatedPassword);

        return new CertificateAuthority(created, leafLifetime ?? TimeSpan.FromDays(90));
    }

    /// <summary>
    /// Liefert ein Leaf-Zertifikat fuer einen Host, aus dem Cache oder neu
    /// ausgestellt. Der Cache ist nach Hostname geschluesselt; SAN ist
    /// genau dieser eine Name.
    /// </summary>
    public X509Certificate2 GetOrCreateLeaf(string hostName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        return _leafCache.GetOrAdd(hostName, CreateLeaf);
    }

    public void Dispose()
    {
        foreach (var leaf in _leafCache.Values)
        {
            leaf.Dispose();
        }

        _leafCache.Clear();
        _caCertificate.Dispose();
    }

    private static X509Certificate2 CreateRoot(string commonName)
    {
        using var rsa = RSA.Create(3072);

        var request = new CertificateRequest(
            $"CN={commonName}, O=Cordon, OU=Local Inspection",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true,
            hasPathLengthConstraint: true,
            pathLengthConstraint: 0,
            critical: true));

        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
            critical: true));

        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        // Die CA wird NICHT in den Trust-Store geschrieben. Sie wird nur
        // dem Agenten uebergeben, der Interception angefordert hat.
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(10));

        // CreateSelfSigned liefert ein Zertifikat, dessen privater Schluessel
        // an den Schluessel-Container des aktuellen Benutzers gebunden ist.
        // Der Umweg ueber PKCS#12 macht den Schluessel exportierbar und damit
        // spaeter erneut ladbar - ohne das waere das Zertifikat nach einem
        // Dienst-Neustart unbrauchbar.
        return new X509Certificate2(
            certificate.Export(X509ContentType.Pkcs12),
            (string?)null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
    }

    private X509Certificate2 CreateLeaf(string hostName)
    {
        using var rsa = RSA.Create(2048);

        var subjectName = new X500DistinguishedName($"CN={hostName}");
        var request = new CertificateRequest(
            subjectName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false,
            hasPathLengthConstraint: false,
            pathLengthConstraint: 0,
            critical: true));

        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: true));

        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")],
            critical: false));

        var sanBuilder = new SubjectAlternativeNameBuilder();

        // Nur ein SAN, exakt der angeforderte Host. Kein Wildcard: ein
        // Wildcard-Leaf wuerde bei einem Fehler in der Zielpruefung gleich
        // eine ganze Domain abdecken.
        if (System.Net.IPAddress.TryParse(hostName, out var ipAddress))
        {
            sanBuilder.AddIpAddress(ipAddress);
        }
        else
        {
            sanBuilder.AddDnsName(hostName);
        }

        request.CertificateExtensions.Add(sanBuilder.Build());
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var serial = RandomNumberGenerator.GetBytes(16);

        using var issued = request.Create(
            _caCertificate,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.Add(_leafLifetime),
            serial);

        // Mit privatem Schluessel zusammenfuehren, damit SslStream das
        // Zertifikat als Server verwenden kann.
        return new X509Certificate2(
            issued.Export(X509ContentType.Pkcs12),
            (string?)null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
    }
}

/// <summary>
/// Baut die <see cref="SslServerAuthenticationOptions"/> fuer eine
/// Interception-Sitzung.
/// </summary>
public static class TlsInterception
{
    public static SslServerAuthenticationOptions CreateServerOptions(
        CertificateAuthority authority,
        string hostName)
    {
        ArgumentNullException.ThrowIfNull(authority);

        return new SslServerAuthenticationOptions
        {
            ServerCertificate = authority.GetOrCreateLeaf(hostName),

            // Kein Clientzertifikat: der Agent ist ueber die Pipe
            // authentifiziert, nicht ueber TLS. Ein Clientzertifikat wuerde
            // eine zweite, schwaecher begruendete Identitaet einfuehren.
            ClientCertificateRequired = false,
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                | System.Security.Authentication.SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };
    }
}
