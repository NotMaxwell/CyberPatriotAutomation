// =============================================================================
// PinnacleCyPat - README service resolution tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using FluentAssertions;
using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Utilities;
using Xunit;

namespace PinnacleCyPat.Tests;

/// <summary>
/// A README names services the way a person would, and more than one task has to
/// agree on what it meant.
/// </summary>
/// <remarks>
/// The tasks used to disagree: service management knew "RDP" meant TermService
/// and protected it, while security hardening set fDenyTSConnections=1 without
/// consulting the README at all. The service kept running and every connection
/// to it was refused - the worst of both, and a lost point.
/// </remarks>
public class ReadmeServicesTests
{
    [Theory]
    [InlineData("Remote Desktop", "TermService")]
    [InlineData("Remote Desktop Services", "TermService")]
    [InlineData("RDP", "TermService")]
    [InlineData("Terminal Services", "TermService")]
    [InlineData("CCS Client", "CCSClient")]
    [InlineData("Internet Connection Sharing", "SharedAccess")]
    public void DisplayNamesResolveToServiceNames(string displayName, string expected)
    {
        ReadmeServices.Resolve(displayName).Should().Be(expected);
    }

    [Fact]
    public void AnUnknownNameIsLeftAlone()
    {
        // A service the table does not know is passed through, so a README naming
        // a real service name directly still works.
        ReadmeServices.Resolve("SomeVendorSvc").Should().Be("SomeVendorSvc");
    }

    [Fact]
    public void ResolutionIsCaseInsensitiveAndTrimmed()
    {
        ReadmeServices.Resolve("  remote desktop  ").Should().Be("TermService");
    }

    /// <summary>
    /// However the README spells it, the answer to "is RDP required?" is the same.
    /// </summary>
    [Theory]
    [InlineData("Remote Desktop")]
    [InlineData("Remote Desktop Services")]
    [InlineData("RDP")]
    [InlineData("TermService")]
    public void RemoteDesktopIsRecognisedHoweverTheReadmeSpellsIt(string entry)
    {
        var readme = new ReadmeData { CriticalServices = [entry] };
        ReadmeServices.IsRemoteDesktopRequired(readme).Should().BeTrue();
    }

    [Fact]
    public void RemoteDesktopIsNotRequiredWhenTheReadmeDoesNotSaySo()
    {
        var readme = new ReadmeData { CriticalServices = ["CCS Client", "Windows Update"] };
        ReadmeServices.IsRemoteDesktopRequired(readme).Should().BeFalse();
    }

    /// <summary>
    /// No README means no instruction either way, so the hardening default wins.
    /// </summary>
    [Fact]
    public void WithNoReadmeRemoteDesktopIsNotRequired()
    {
        ReadmeServices.IsRemoteDesktopRequired(null).Should().BeFalse();
    }

    [Fact]
    public void OtherCriticalServicesAreRecognisedToo()
    {
        var readme = new ReadmeData { CriticalServices = ["CCS Client"] };
        ReadmeServices.IsCritical(readme, "CCSClient").Should().BeTrue();
        ReadmeServices.IsCritical(readme, "TermService").Should().BeFalse();
    }
}

/// <summary>
/// The four SMB signing settings Local Security Policy exposes.
/// </summary>
/// <remarks>
/// Only the server half was ever applied, because the task that sets the client
/// half was never wired to a command-line flag.
/// </remarks>
public class GroupPolicyCoverageTests
{
    [Fact]
    public void TheGroupPolicyTaskIsReachableFromTheCommandLine()
    {
        Program.FirstUnknownArgument(["--group-policy"]).Should().BeNull();
        Program.FirstUnknownArgument(["-g"]).Should().BeNull();
    }

    [Fact]
    public void TheMenuOffersTheGroupPolicyTask()
    {
        PinnacleCyPat.Core.Tui.OfferedFlags.Should().Contain("--group-policy");
    }
}
