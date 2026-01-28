// =============================================================================
// CyberPatriot Automation Tool - SharedFoldersAuditTask Tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Tasks;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

public class SharedFoldersAuditTaskTests
{
    [Fact]
    public void Name_And_Description_ShouldBeCorrect()
    {
        var task = new SharedFoldersAuditTask();
        task.Name.Should().Be("Shared Folders Audit");
        task.Description.Should().Contain("shared folders");
    }

    [Fact]
    public async Task ReadSystemStateAsync_ShouldReturnSystemInfo()
    {
        var task = new SharedFoldersAuditTask();
        var info = await task.ReadSystemStateAsync();
        info.Should().NotBeNull();
    }
}
