// =============================================================================
// PinnacleCyPat - ReadmeParser correctness tests
// =============================================================================

using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Utilities;
using FluentAssertions;
using Xunit;

namespace PinnacleCyPat.Tests;

/// <summary>
/// Each case here pins a defect that shipped in the original parser.
/// </summary>
public class ReadmeParserCorrectnessTests
{
    private static async Task<ReadmeData> ParseAsync(string html)
    {
        var path = Path.Combine(Path.GetTempPath(), $"cpa_{Guid.NewGuid():N}.html");
        await File.WriteAllTextAsync(path, html);
        try
        {
            return await ReadmeParser.ParseHtmlReadmeAsync(path);
        }
        finally
        {
            File.Delete(path);
        }
    }

    // --- Operating system detection -----------------------------------------

    [Fact]
    public async Task OsDetection_ShouldSeeThroughMarkup()
    {
        var html =
            "<html><head><title>Round 1</title></head><body>"
            + "<h1>Training Round <b>Windows 10</b> README</h1></body></html>";
        (await ParseAsync(html)).OperatingSystem.Should().Be("Windows 10");
    }

    [Fact]
    public async Task OsDetection_ShouldSeeThroughNonBreakingSpaces()
    {
        // &nbsp; decodes to U+00A0, which never equals the plain space that the
        // old substring search looked for.
        var html = "<html><body><h1>Windows&nbsp;11 Image</h1></body></html>";
        (await ParseAsync(html)).OperatingSystem.Should().Be("Windows 11");
    }

    [Fact]
    public async Task OsDetection_ShouldPreferTheHeadlineOverProse()
    {
        // A Windows 11 image whose body warns against rolling back to Windows 10.
        var html =
            "<html><head><title>Windows 11 Enterprise README</title></head><body>"
            + "<p>Do not attempt to go back to Windows 10 using recovery options.</p>"
            + "</body></html>";
        (await ParseAsync(html)).OperatingSystem.Should().Be("Windows 11");
    }

    [Fact]
    public async Task OsDetection_ShouldNotReportServerAsDesktop()
    {
        var html = "<html><body><h1>Windows Server 2022 Standard</h1></body></html>";
        (await ParseAsync(html)).OperatingSystem.Should().Be("Windows Server 2022");
    }

    [Fact]
    public async Task OsDetection_ShouldStillReportUnknownWhenAbsent()
    {
        var html = "<html><body><h1>Some Appliance README</h1></body></html>";
        (await ParseAsync(html)).OperatingSystem.Should().Be("Unknown");
    }

    // --- User lists ----------------------------------------------------------

    [Fact]
    public async Task UserList_SeparatedByBrTags_ShouldStillYieldUsers()
    {
        // Only a <pre> block carries real newlines. A list written with <br>
        // collapsed to one line once tags were stripped, and the whole block was
        // rejected as a single over-long "username" - so no users were found.
        var html =
            "<html><body><h1>Windows 10</h1>"
            + "<h2>Authorized Administrators</h2>"
            + "<p>Authorized Administrators<br>alice (you)<br>password: Alice#Pass1<br>"
            + "bob<br>password: Bob#Pass2<br>Authorized Users<br>carol<br>dave</p>"
            + "</body></html>";

        var data = await ParseAsync(html);

        data.Administrators.Select(a => a.Username).Should().Contain(new[] { "alice", "bob" });
        data.Users.Select(u => u.Username).Should().Contain(new[] { "carol", "dave" });
        data.Administrators.Single(a => a.Username == "alice").IsPrimaryUser.Should().BeTrue();
        data.Administrators.Single(a => a.Username == "bob").Password.Should().Be("Bob#Pass2");
    }

    // --- Services ------------------------------------------------------------

    private const string NegatedDisableReadme =
        "<html><body><h1>Windows 10 Image</h1>"
        + "<h2>Competition Guidelines</h2><ul>"
        + "<li>Do not stop or disable the CCS Client service.</li>"
        + "<li>Do not stop or disable the Windows Update service.</li>"
        + "<li>Never disable the Windows Defender service.</li>"
        + "<li>Disable the Telnet service.</li>"
        + "</ul></body></html>";

    [Theory]
    [InlineData("CCS Client")]
    [InlineData("Windows Update")]
    [InlineData("Windows Defender")]
    public async Task DoNotStopOrDisable_ShouldNotQueueTheServiceForDisabling(string service)
    {
        // The original lookbehind only covered a literal "do not " immediately
        // before "disable", so the intervening "stop or " let a critical service
        // be queued for disabling.
        var data = await ParseAsync(NegatedDisableReadme);

        data.ProhibitedServices.Should().NotContain(s => s.Equals(service, StringComparison.OrdinalIgnoreCase));
        data.CriticalServices.Should().Contain(s => s.Equals(service, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AGenuineDisableInstruction_ShouldStillBeHonoured()
    {
        var data = await ParseAsync(NegatedDisableReadme);
        data.ProhibitedServices.Should().Contain(s => s.Equals("Telnet", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ACriticalService_ShouldNeverAlsoBeProhibited()
    {
        var data = await ParseAsync(NegatedDisableReadme);
        foreach (var critical in data.CriticalServices)
        {
            data.ProhibitedServices
                .Should()
                .NotContain(p => p.Equals(critical, StringComparison.OrdinalIgnoreCase));
        }
    }

    // --- Software ------------------------------------------------------------

    [Fact]
    public async Task SoftwareParsing_ShouldRejectProseAndScopeLatest()
    {
        var html =
            "<html><body><h1>Windows 10 Image</h1><h2>Software</h2>"
            + "<p>Employees must have access to the latest stable version of Firefox for company use.</p>"
            + "<p>Standard users should not have access to administrative tools.</p>"
            + "<p>This machine should be using Thunderbird.</p>"
            + "</body></html>";

        var data = await ParseAsync(html);
        var names = data.RequiredSoftware.Select(s => s.Name).ToList();

        names.Should().Contain("Firefox");
        names.Should().NotContain(n => n.Equals("administrative tools", StringComparison.OrdinalIgnoreCase));

        data.RequiredSoftware.Single(s => s.Name == "Firefox").ShouldBeLatest.Should().BeTrue();

        // "Thunderbird" is not described as latest; the document merely contains
        // the word elsewhere, which used to be enough to flag it.
        var thunderbird = data.RequiredSoftware.FirstOrDefault(s => s.Name == "Thunderbird");
        if (thunderbird != null)
            thunderbird.ShouldBeLatest.Should().BeFalse();
    }

    // --- Groups --------------------------------------------------------------

    [Fact]
    public async Task GroupRequirements_ShouldParseEveryGroupNotJustTheFirst()
    {
        var html =
            "<html><body><h1>Windows 11</h1>"
            + "<p>Make a group called allsafe and add ggoddard, ealderson, amoss.</p>"
            + "<p>Create a new group called auditors and add lchong, pprice.</p>"
            + "</body></html>";

        var data = await ParseAsync(html);

        data.GroupRequirements.Select(g => g.GroupName)
            .Should()
            .Contain(new[] { "allsafe", "auditors" });
    }

    /// <summary>
    /// The sentence below is verbatim from a competition README, and the run it
    /// produced recorded
    /// <c>Members: users, ggoddard, ealderson, amoss, lchong, group</c>.
    /// </summary>
    /// <remarks>
    /// The member capture is prose, and the regex only knew the phrasing
    /// "add the following users to the X group:". Against "add the users ...
    /// into the group" the optional prefix did not match, so the connectives
    /// were captured with the names. "the", "and" and "into" were filtered as
    /// common words; "users" and "group" were not, and the run issued
    /// <c>net localgroup allsafe "group" /add</c>.
    /// </remarks>
    [Fact]
    public async Task GroupMembers_ShouldNotIncludeTheConnectiveProse()
    {
        var html =
            "<html><body><h1>Windows 11</h1><p>Please make a group called allsafe "
            + "and add the users ggoddard, ealderson, amoss, and lchong into the group.</p>"
            + "</body></html>";

        var data = await ParseAsync(html);

        var group = data.GroupRequirements.Single(g => g.GroupName == "allsafe");
        group.Members.Should().Equal("ggoddard", "ealderson", "amoss", "lchong");
    }

    /// <summary>The phrasing the regex already handled must keep working.</summary>
    [Fact]
    public async Task GroupMembers_ShouldStillParseTheFollowingUsersPhrasing()
    {
        var html =
            "<html><body><h1>Windows 11</h1><p>Create a new group called auditors and add "
            + "the following users to the auditors group: lchong, pprice.</p></body></html>";

        var data = await ParseAsync(html);

        data.GroupRequirements.Single(g => g.GroupName == "auditors")
            .Members.Should()
            .Equal("lchong", "pprice");
    }

    [Theory]
    // The two that reached a live command line.
    [InlineData("the users ggoddard, ealderson into the group", "ggoddard|ealderson")]
    // Other shapes of the same prose.
    [InlineData("the following users: amoss and lchong", "amoss|lchong")]
    [InlineData("these accounts amoss, lchong to the group", "amoss|lchong")]
    [InlineData("users amoss and lchong as members of the group", "amoss|lchong")]
    // No connectives at all - the shape the original tests covered.
    [InlineData("ggoddard, ealderson, amoss", "ggoddard|ealderson|amoss")]
    public void ExtractGroupMembers_KeepsOnlyTheNames(string prose, string expected)
    {
        ReadmeParser.ExtractGroupMembers(prose).Should().Equal(expected.Split('|'));
    }
}
