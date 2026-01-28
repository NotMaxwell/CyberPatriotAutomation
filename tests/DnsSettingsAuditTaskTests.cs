// =============================================================================
// CyberPatriot Automation Tool - DnsSettingsAuditTask Tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Tasks;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

public class DnsSettingsAuditTaskTests
{
    [Fact]
    public void Name_And_Description_ShouldBeCorrect()
    {
        var task = new DnsSettingsAuditTask();
        task.Name.Should().Be("DNS Settings Audit");
        task.Description.Should().Contain("DNS settings");
    }

    [Fact]
    public async Task ReadSystemStateAsync_ShouldReturnSystemInfo()
    {
        var task = new DnsSettingsAuditTask();
        var info = await task.ReadSystemStateAsync();
        info.Should().NotBeNull();
    }
}
