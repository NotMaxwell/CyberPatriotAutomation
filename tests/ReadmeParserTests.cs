// =============================================================================
// CyberPatriot Automation Tool - ReadmeParser Tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

using CyberPatriotAutomation.Core.Utilities;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

/// <summary>
/// Unit tests for ReadmeParser
/// </summary>
public class ReadmeParserTests
{
    private const string SampleReadmePath = "../SampleData/sampleReadme.html";

    [Fact]
    public async Task ParseHtmlReadmeAsync_NonExistentFile_ShouldReturnEmptyData()
    {
        var result = await ReadmeParser.ParseHtmlReadmeAsync("nonexistent.html");

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractTitle()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.Title.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractOperatingSystem()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.OperatingSystem.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractAdministrators()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.Administrators.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractAdminPasswords()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.Administrators.Should().Contain(a => !string.IsNullOrEmpty(a.Password));
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractUsers()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.Users.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractCriticalServices()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.CriticalServices.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractGuidelines()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.Guidelines.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractRequiredSoftware()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.RequiredSoftware.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractGroupRequirements()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.GroupRequirements.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ParseHtmlReadmeAsync_ShouldExtractUsersToCreate()
    {
        if (!File.Exists(SampleReadmePath)) return;

        var result = await ReadmeParser.ParseHtmlReadmeAsync(SampleReadmePath);

        result.UsersToCreate.Should().NotBeEmpty();
    }
}
