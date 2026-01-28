// =============================================================================
// CyberPatriot Automation Tool - SuspiciousScheduledTasksAuditTask Tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Tasks;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

public class SuspiciousScheduledTasksAuditTaskTests
{
    [Fact]
    public void Name_And_Description_ShouldBeCorrect()
    {
        var task = new SuspiciousScheduledTasksAuditTask();
        task.Name.Should().Be("Suspicious Scheduled Tasks Audit");
        task.Description.Should().Contain("scheduled tasks");
    }

    [Fact]
    public async Task ReadSystemStateAsync_ShouldReturnSystemInfo()
    {
        var task = new SuspiciousScheduledTasksAuditTask();
        var info = await task.ReadSystemStateAsync();
        info.Should().NotBeNull();
    }
}
