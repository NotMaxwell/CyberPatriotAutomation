// =============================================================================
// CyberPatriot Automation Tool - README discovery tests
// =============================================================================

using CyberPatriotAutomation.Core;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

/// <summary>
/// A standard competition image ships C:\CyberPatriot\README.url - an Internet
/// Shortcut naming a remote document - rather than the README itself, and the
/// desktop link chains through it. These cover that resolution.
/// </summary>
public class ReadmeDiscoveryTests
{
    [Fact]
    public void DefaultReadmePaths_ShouldLeadWithTheStandardImageLocation()
    {
        AppConfig.DefaultReadmePaths[0].Should().Be(@"C:\CyberPatriot\README.url");
        AppConfig.DefaultReadmePaths.Should().Contain(p => p.EndsWith("README.html"));
    }

    [Fact]
    public void ParseInternetShortcut_ShouldExtractTheUrlValue()
    {
        var contents = "[InternetShortcut]\r\nURL=file:///C:/CyberPatriot/README.html\r\nIconIndex=0\r\n";
        AppConfig.ParseInternetShortcut(contents).Should().Be("file:///C:/CyberPatriot/README.html");
    }

    [Fact]
    public void ParseInternetShortcut_ShouldBeCaseInsensitiveAndTolerateOtherKeys()
    {
        var contents = "[InternetShortcut]\r\nIDList=\r\nurl=C:\\CyberPatriot\\README.html\r\n";
        AppConfig.ParseInternetShortcut(contents).Should().Be(@"C:\CyberPatriot\README.html");
    }

    [Theory]
    [InlineData("file:///C:/CyberPatriot/README.html")]
    [InlineData("file://C:/CyberPatriot/README.html")]
    [InlineData("file://localhost/C:/CyberPatriot/README.html")]
    public void ToLocalPath_ShouldConvertEveryFileUriForm(string uri)
    {
        AppConfig.ToLocalPath(uri).Should().Be(@"C:\CyberPatriot\README.html");
    }

    [Fact]
    public void ToLocalPath_ShouldDecodePercentEscapes()
    {
        AppConfig
            .ToLocalPath("file:///C:/Cyber%20Patriot/READ%20ME.html")
            .Should()
            .Be(@"C:\Cyber Patriot\READ ME.html");
    }

    [Fact]
    public void ToLocalPath_ShouldKeepAnAbsolutePosixRoot()
    {
        // Stripping every leading slash and swapping separators would turn this
        // absolute path into a relative one.
        AppConfig
            .ToLocalPath("file:///tmp/CyberPatriot/README.html")
            .Should()
            .Be("/tmp/CyberPatriot/README.html");
    }

    [Fact]
    public void ToLocalPath_ShouldRejectRemoteTargets()
    {
        // Nothing on disk to open, so it must not be returned as a path.
        AppConfig.ToLocalPath("https://example.org/readme.html").Should().BeNull();
        AppConfig.ToLocalPath("").Should().BeNull();
    }

    [Fact]
    public void IsRemoteTarget_ShouldInspectOnlyTheScheme()
    {
        // Sample addresses: the real one is unique per image and read from the
        // shortcut at run time, so no host or path is baked into the tool.
        AppConfig.IsRemoteTarget("https://example-bucket.s3.amazonaws.com/r/readme.html").Should().BeTrue();
        AppConfig.IsRemoteTarget("  HTTPS://EXAMPLE.ORG/x  ").Should().BeTrue();
        AppConfig.IsRemoteTarget(@"C:\CyberPatriot\README.html").Should().BeFalse();
        AppConfig.IsRemoteTarget("file:///C:/CyberPatriot/README.html").Should().BeFalse();
    }

    [Fact]
    public async Task ResolveReadmeCandidate_ShouldFollowAUrlShortcutToTheDocument()
    {
        var root = Path.Combine(Path.GetTempPath(), $"cpa_url_{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var doc = Path.Combine(root, "README.html");
            await File.WriteAllTextAsync(doc, "<html><h1>Windows 11</h1></html>");

            var shortcut = Path.Combine(root, "README.url");
            var uri = "file://" + doc.Replace('\\', '/');
            await File.WriteAllTextAsync(shortcut, $"[InternetShortcut]\r\nURL={uri}\r\n");

            var resolved = await AppConfig.ResolveReadmeCandidateAsync(shortcut);
            resolved.Should().EndWith("README.html");
            File.Exists(resolved).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ResolveReadmeCandidate_ShouldFollowShortcutChains()
    {
        // A real image chains: desktop .lnk -> README.url -> the document.
        // Stopping after one hop returns the .url, and parsing that INI file as
        // HTML produces a README with no title and no detectable OS.
        var root = Path.Combine(Path.GetTempPath(), $"cpa_chain_{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var doc = Path.Combine(root, "README.html");
            await File.WriteAllTextAsync(doc, "<html><h1>Windows 11</h1></html>");

            var inner = Path.Combine(root, "inner.url");
            await File.WriteAllTextAsync(
                inner,
                $"[InternetShortcut]\r\nURL=file://{doc.Replace('\\', '/')}\r\n"
            );

            var outer = Path.Combine(root, "README.url");
            await File.WriteAllTextAsync(
                outer,
                $"[InternetShortcut]\r\nURL=file://{inner.Replace('\\', '/')}\r\n"
            );

            var resolved = await AppConfig.ResolveReadmeCandidateAsync(outer);
            resolved.Should().EndWith("README.html");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ResolveReadmeCandidate_ShouldTerminateOnAShortcutLoop()
    {
        var root = Path.Combine(Path.GetTempPath(), $"cpa_loop_{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var a = Path.Combine(root, "a.url");
            var b = Path.Combine(root, "b.url");
            await File.WriteAllTextAsync(
                a,
                $"[InternetShortcut]\r\nURL=file://{b.Replace('\\', '/')}\r\n"
            );
            await File.WriteAllTextAsync(
                b,
                $"[InternetShortcut]\r\nURL=file://{a.Replace('\\', '/')}\r\n"
            );

            // Must give up rather than spin forever.
            (await AppConfig.ResolveReadmeCandidateAsync(a)).Should().BeNull();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ResolveReadmeCandidate_ShouldRejectAStaleShortcut()
    {
        var root = Path.Combine(Path.GetTempPath(), $"cpa_dead_{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var shortcut = Path.Combine(root, "README.url");
            await File.WriteAllTextAsync(
                shortcut,
                "[InternetShortcut]\r\nURL=file:///C:/nope/does-not-exist.html\r\n"
            );

            // A stale shortcut must not masquerade as a README.
            (await AppConfig.ResolveReadmeCandidateAsync(shortcut)).Should().BeNull();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ResolveReadmeCandidate_ShouldReadAUtf16EncodedShortcut()
    {
        // Windows tools often write UTF-16 with a BOM; a strict UTF-8 read
        // rejects it outright and the shortcut is silently discarded.
        var root = Path.Combine(Path.GetTempPath(), $"cpa_utf16_{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var doc = Path.Combine(root, "README.html");
            await File.WriteAllTextAsync(doc, "<html><h1>Windows 11</h1></html>");

            var shortcut = Path.Combine(root, "README.url");
            var text = $"[InternetShortcut]\r\nURL=file://{doc.Replace('\\', '/')}\r\n";
            await File.WriteAllBytesAsync(
                shortcut,
                new System.Text.UnicodeEncoding(false, true).GetPreamble()
                    .Concat(System.Text.Encoding.Unicode.GetBytes(text))
                    .ToArray()
            );

            var resolved = await AppConfig.ResolveReadmeCandidateAsync(shortcut);
            resolved.Should().EndWith("README.html");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ExpandWildcardPath_ShouldEnumerateTheStarredPosition()
    {
        var root = Path.Combine(Path.GetTempPath(), $"cpa_wild_{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(root, "alice", "Desktop"));
        Directory.CreateDirectory(Path.Combine(root, "bob", "Desktop"));
        try
        {
            File.WriteAllText(Path.Combine(root, "bob", "Desktop", "README.html"), "<html></html>");

            var matches = AppConfig.ExpandWildcardPath(Path.Combine(root, "*", "Desktop", "README.html"));
            matches.Should().ContainSingle().Which.Should().Contain("bob");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ExpandWildcardPath_ShouldReturnNothingWhenNoneMatch()
    {
        var root = Path.Combine(Path.GetTempPath(), $"cpa_wild_empty_{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(root, "alice", "Desktop"));
        try
        {
            AppConfig
                .ExpandWildcardPath(Path.Combine(root, "*", "Desktop", "README.html"))
                .Should()
                .BeEmpty();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
