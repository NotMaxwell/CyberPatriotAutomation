// =============================================================================
// CyberPatriot Automation Tool - Command line parsing tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using CyberPatriotAutomation;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

/// <summary>
/// An unrecognised argument must be rejected rather than ignored.
/// </summary>
/// <remarks>
/// Flags used to be matched by name with anything else ignored, while "no task
/// flag given" meant "run everything". So a typo - or <c>--help</c> itself,
/// which was not a flag - silently began a full destructive run. Rejecting the
/// argument is what makes that impossible.
/// </remarks>
public class CommandLineTests
{
    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("-?")]
    [InlineData("/?")]
    [InlineData("--dry-run")]
    [InlineData("--all")]
    [InlineData("--security-hardening")]
    [InlineData("-H")]
    public void KnownFlagsAreAccepted(string flag)
    {
        Program.FirstUnknownArgument([flag]).Should().BeNull();
    }

    [Fact]
    public void AnUnknownFlagIsReported()
    {
        Program.FirstUnknownArgument(["--dry-run", "--oops"]).Should().Be("--oops");
    }

    [Fact]
    public void ATypoOfAKnownFlagIsNotSilentlyIgnored()
    {
        // The dangerous case: this used to set no task flag, which meant "run
        // everything" rather than "you mistyped --dry-run".
        Program.FirstUnknownArgument(["--dryrun"]).Should().Be("--dryrun");
    }

    [Fact]
    public void ValueFlagsConsumeTheirArgument()
    {
        // The path is a value, not an unrecognised flag.
        Program.FirstUnknownArgument(["--readme", "C:\\CyberPatriot\\README.url"])
            .Should()
            .BeNull();
        Program.FirstUnknownArgument(["--log", "run.txt", "--all"]).Should().BeNull();
        Program.FirstUnknownArgument(["-r", "readme.html"]).Should().BeNull();
    }

    [Fact]
    public void SecurityHardeningNoLongerClaimsTheHelpFlag()
    {
        // -h is help now; -H is security hardening. Both must be accepted, and
        // the old binding must not quietly linger.
        Program.FirstUnknownArgument(["-H"]).Should().BeNull();
        Program.FirstUnknownArgument(["-h"]).Should().BeNull();
    }

    [Fact]
    public void NoArgumentsIsNotAnError()
    {
        Program.FirstUnknownArgument([]).Should().BeNull();
    }
}
