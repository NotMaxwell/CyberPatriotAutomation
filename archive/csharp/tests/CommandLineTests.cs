// =============================================================================
// PinnacleCyPat - Command line parsing tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using PinnacleCyPat;
using PinnacleCyPat.Core;
using FluentAssertions;
using Xunit;

namespace PinnacleCyPat.Tests;

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

    [Theory]
    [InlineData("--tui")]
    [InlineData("-i")]
    public void TheInteractiveMenuHasAFlag(string flag)
    {
        Program.FirstUnknownArgument([flag]).Should().BeNull();
    }

    /// <summary>
    /// The five tasks that used to run only under <c>--all</c> are selectable.
    /// </summary>
    /// <remarks>
    /// The menu offers every task by flag, so a flag it names but the parser
    /// does not accept would exit 2 with "Unrecognised argument" the moment that
    /// task was picked.
    /// </remarks>
    [Theory]
    [InlineData("--software-management")]
    [InlineData("--shared-folders")]
    [InlineData("--hosts-file")]
    [InlineData("--dns-settings")]
    [InlineData("--scheduled-tasks")]
    public void TasksOnceReachableOnlyViaAllHaveTheirOwnFlag(string flag)
    {
        Program.FirstUnknownArgument([flag]).Should().BeNull();
    }

    /// <summary>Every flag the menu can emit must be one the parser accepts.</summary>
    [Fact]
    public void EveryMenuFlagIsAcceptedByTheParser()
    {
        foreach (var flag in Tui.OfferedFlags)
        {
            Program
                .FirstUnknownArgument([flag])
                .Should()
                .BeNull($"the menu offers {flag}, so the parser has to accept it");
        }
    }
}
