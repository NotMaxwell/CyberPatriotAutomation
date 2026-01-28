// =============================================================================
// CyberPatriot Automation Tool - HostsFileAuditTask Tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Tasks;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

public class HostsFileAuditTaskTests
{
    [Fact]
    public void Name_And_Description_ShouldBeCorrect()
    {
        var task = new HostsFileAuditTask();
        task.Name.Should().Be("Hosts File Audit");
        task.Description.Should().Contain("hosts file");
    }

    [Fact]
    public async Task ReadSystemStateAsync_ShouldReturnSystemInfo()
    {
        var task = new HostsFileAuditTask();
        var info = await task.ReadSystemStateAsync();
        info.Should().NotBeNull();
    }
}
