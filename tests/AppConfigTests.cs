// =============================================================================
// CyberPatriot Automation Tool - AppConfig Tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

using CyberPatriotAutomation.Core;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

/// <summary>
/// Unit tests for AppConfig
/// </summary>
public class AppConfigTests
{
    [Fact]
    public void Version_ShouldBeDefined()
    {
        AppConfig.Version.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void CCSClientServiceName_ShouldBeDefined()
    {
        AppConfig.CCSClientServiceName.Should().NotBeNullOrEmpty();
        AppConfig.CCSClientServiceName.Should().Contain("CCS");
    }

    [Fact]
    public void ScoringReportShortcut_ShouldBeDefined()
    {
        AppConfig.ScoringReportShortcut.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void DefaultReadmePaths_ShouldNotBeEmpty()
    {
        AppConfig.DefaultReadmePaths.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void DefaultReadmePaths_ShouldContainCommonLocations()
    {
        var paths = AppConfig.DefaultReadmePaths;

        paths.Should().Contain(p => p.Contains("Desktop"));
    }

    [Fact]
    public void SecurePasswords_ShouldHaveEnoughPasswords()
    {
        AppConfig.SecurePasswords.Should().HaveCountGreaterOrEqualTo(10);
    }

    [Fact]
    public void SecurePasswords_ShouldBeUnique()
    {
        var passwords = AppConfig.SecurePasswords;

        passwords.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void SecurePasswords_ShouldMeetComplexityRequirements()
    {
        foreach (var password in AppConfig.SecurePasswords)
        {
            // At least 12 characters
            password.Length.Should().BeGreaterOrEqualTo(12);

            // Has uppercase
            password.Should().MatchRegex("[A-Z]");

            // Has lowercase
            password.Should().MatchRegex("[a-z]");

            // Has digit
            password.Should().MatchRegex("[0-9]");

            // Has special character
            password.Should().MatchRegex("[^a-zA-Z0-9]");
        }
    }
}
