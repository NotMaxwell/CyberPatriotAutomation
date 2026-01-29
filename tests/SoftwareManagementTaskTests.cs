// =============================================================================
// CyberPatriot Automation Tool - SoftwareManagementTask Tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Tasks;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

public class SoftwareManagementTaskTests
{
    [Fact]
    public void Name_And_Description_ShouldBeCorrect()
    {
        var task = new SoftwareManagementTask();
        task.Name.Should().Be("Software Management");
        task.Description.Should().Contain("Removes prohibited software");
    }

    [Fact]
    public async Task ReadSystemStateAsync_ShouldReturnSystemInfo()
    {
        var task = new SoftwareManagementTask();
        var info = await task.ReadSystemStateAsync();
        info.Should().NotBeNull();
    }
}
