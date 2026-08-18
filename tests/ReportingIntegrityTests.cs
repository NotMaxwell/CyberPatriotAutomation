// =============================================================================
// CyberPatriot Automation Tool - Reporting integrity tests
// =============================================================================

using CyberPatriotAutomation.Core.Models;
using CyberPatriotAutomation.Core.Tasks;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

/// <summary>
/// The tool's summary is only useful if it reflects what actually happened.
/// Each case here pins a way it previously did not.
/// </summary>
public class ReportingIntegrityTests
{
    [Fact]
    public void CompletionRate_ShouldNotReportFullCompletionForAFailedTask()
    {
        // No task populates ItemsAttempted, so the old flat 100% fallback meant
        // the headline completion rate read 100% however many tasks had failed.
        var failed = new TaskResult { TaskName = "x", Success = false };
        failed.CompletionRate.Should().Be(0);

        var succeeded = new TaskResult { TaskName = "x", Success = true };
        succeeded.CompletionRate.Should().Be(100);
    }

    [Fact]
    public void CompletionRate_ShouldStillUseItemCountsWhenReported()
    {
        var result = new TaskResult
        {
            TaskName = "x",
            Success = false,
            ItemsAttempted = 10,
            ItemsSucceeded = 7,
            ItemsSkipped = 1,
        };
        result.CompletionRate.Should().BeApproximately(80, 0.001);
    }

    // --- net share parsing ---------------------------------------------------

    private const string NetShareOutput =
        "Share name   Resource                        Remark\r\n"
        + "\r\n"
        + "-------------------------------------------------------------------------------\r\n"
        + "C$           C:\\                             Default share\r\n"
        + "IPC$                                         Remote IPC\r\n"
        + "ADMIN$       C:\\Windows                      Remote Admin\r\n"
        + "Docs         C:\\Users\\Public\\Docs\r\n"
        + "The command completed successfully.\r\n";

    [Fact]
    public void ParseShares_ShouldIgnoreHeaderAndStatusLines()
    {
        var shares = SharedFoldersAuditTask.ParseShares(NetShareOutput);

        shares.Should().Equal("C$", "IPC$", "ADMIN$", "Docs");
        // "Share" (header) and "The" (status line) used to be parsed as shares,
        // so the task tried to delete them.
        shares.Should().NotContain("Share");
        shares.Should().NotContain("The");
    }

    // --- hosts file ----------------------------------------------------------

    [Theory]
    [InlineData("127.0.0.1\tlocalhost")]
    [InlineData("127.0.0.1   localhost")]
    [InlineData("::1   localhost")]
    public void IsAllowedEntry_ShouldAcceptLocalhostRegardlessOfSpacing(string entry)
    {
        // Exact string comparison against a fixed-spacing constant classified a
        // tab-separated entry as unauthorized and deleted the legitimate
        // localhost mapping.
        HostsFileAuditTask.IsAllowedEntry(entry).Should().BeTrue();
    }

    [Theory]
    [InlineData("127.0.0.1 www.google.com")]
    [InlineData("0.0.0.0 update.microsoft.com")]
    public void IsAllowedEntry_ShouldRejectRedirectedDomains(string entry)
    {
        HostsFileAuditTask.IsAllowedEntry(entry).Should().BeFalse();
    }

    // --- registry verification ----------------------------------------------

    private const string RegQueryOutput =
        "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\r\n"
        + "    dontdisplaylastusername    REG_DWORD    0x1\r\n"
        + "    DisableCAD    REG_DWORD    0x0\r\n";

    [Fact]
    public void ParseRegDword_ShouldReadTheNamedValue()
    {
        GroupPolicyTask.ParseRegDword(RegQueryOutput, "dontdisplaylastusername").Should().Be(1u);
        GroupPolicyTask.ParseRegDword(RegQueryOutput, "DisableCAD").Should().Be(0u);
    }

    [Fact]
    public void ParseRegDword_ShouldBeCaseInsensitiveOnTheValueName()
    {
        GroupPolicyTask.ParseRegDword(RegQueryOutput, "DONTDISPLAYLASTUSERNAME").Should().Be(1u);
    }

    [Fact]
    public void ParseRegDword_ShouldReturnNullWhenAbsent()
    {
        GroupPolicyTask.ParseRegDword(RegQueryOutput, "restrictanonymous").Should().BeNull();
    }

    [Fact]
    public void ParseRegDword_ShouldDistinguishAPresentButWrongValue()
    {
        // The old verify only checked that `reg query` exited 0, so a value
        // present with the wrong contents passed verification.
        GroupPolicyTask.ParseRegDword(RegQueryOutput, "DisableCAD").Should().NotBe(1u);
    }
}
