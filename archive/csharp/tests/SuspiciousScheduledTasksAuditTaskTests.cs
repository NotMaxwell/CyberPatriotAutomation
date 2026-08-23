// =============================================================================
// PinnacleCyPat - SuspiciousScheduledTasksAuditTask Tests
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
using System.Threading.Tasks;
using PinnacleCyPat.Core.Tasks;
using FluentAssertions;
using Xunit;

namespace PinnacleCyPat.Tests;

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
