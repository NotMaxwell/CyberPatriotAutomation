// =============================================================================
// PinnacleCyPat - SoftwareManagementTask Tests
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
using System.Threading.Tasks;
using PinnacleCyPat.Core.Tasks;
using FluentAssertions;
using Xunit;

namespace PinnacleCyPat.Tests;

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
