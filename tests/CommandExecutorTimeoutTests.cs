// =============================================================================
// CyberPatriot Automation Tool - CommandExecutor timeout tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Utilities;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

/// <summary>
/// The timeout has to bound a child that never exits on its own.
/// </summary>
/// <remarks>
/// It previously did not. The exit-wait and both stream reads were awaited
/// together with <c>Task.WhenAll</c>, which completes only when every task does.
/// The stream reads finish when the child's pipes close, which happens when it
/// exits - so for a child that never exits they stayed pending, cancelling the
/// exit-wait left the await pending too, and the timeout did nothing in exactly
/// the case it existed for. In the field that showed up as the tool freezing on
/// "Disable Insecure Services", where `net stop` sat on a "(Y/N)" prompt.
/// </remarks>
public class CommandExecutorTimeoutTests
{
    /// <summary>A command that sleeps far longer than any timeout under test.</summary>
    private static (string Command, string Arguments) SleepForever() =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? ("cmd.exe", "/c ping -n 600 127.0.0.1 > nul")
            : ("/bin/sh", "-c \"sleep 600\"");

    [Fact]
    public async Task ExecuteAsync_ReturnsWhenTheChildNeverExits()
    {
        var (command, arguments) = SleepForever();
        var timeout = TimeSpan.FromSeconds(2);

        var stopwatch = Stopwatch.StartNew();
        var (success, _, error) = await CommandExecutor.ExecuteAsync(
            command,
            arguments,
            timeout
        );
        stopwatch.Stop();

        success.Should().BeFalse("a killed process is not a successful one");
        error.Should().Contain("timed out");

        // Generous upper bound: the assertion is "it returns at all", not the
        // precise timing, which is noisy on a loaded machine.
        stopwatch
            .Elapsed.Should()
            .BeLessThan(
                TimeSpan.FromSeconds(30),
                "the timeout must bound a child that never exits"
            );
    }

    [Fact]
    public async Task ExecuteForExitCodeAsync_ReportsNoExitCodeOnTimeout()
    {
        var (command, arguments) = SleepForever();

        var (exitCode, _, error) = await CommandExecutor.ExecuteForExitCodeAsync(
            command,
            arguments,
            TimeSpan.FromSeconds(2)
        );

        // A killed process has no meaningful exit code; callers that map codes
        // (Chocolatey's 3010/1641) must not read the kill as one of them.
        exitCode.Should().BeNull();
        error.Should().Contain("timed out");
    }

    [Fact]
    public async Task ExecuteAsync_DoesNotBlockOnAChildReadingStdin()
    {
        // `net stop` prompts when a service has dependents. Stdin is redirected
        // and closed so the read hits EOF and the command gives up, rather than
        // waiting for a keypress that is never coming.
        var (command, arguments) = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? ("cmd.exe", "/c set /p X=")
            : ("/bin/sh", "-c \"read line\"");

        var stopwatch = Stopwatch.StartNew();
        await CommandExecutor.ExecuteAsync(command, arguments, TimeSpan.FromSeconds(20));
        stopwatch.Stop();

        // Well under the timeout: this should end at EOF, not be killed.
        stopwatch
            .Elapsed.Should()
            .BeLessThan(
                TimeSpan.FromSeconds(15),
                "a child reading stdin should see EOF immediately, not wait for the timeout"
            );
    }
}
