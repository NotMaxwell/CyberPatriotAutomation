// =============================================================================
// PinnacleCyPat - DnsSettingsAuditTask Tests
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
using System.Threading.Tasks;
using PinnacleCyPat.Core.Tasks;
using FluentAssertions;
using Xunit;

namespace PinnacleCyPat.Tests;

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
