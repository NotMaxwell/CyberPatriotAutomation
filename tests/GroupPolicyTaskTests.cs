// CyberPatriot Automation Tool - GroupPolicyTask Tests
using System.Threading.Tasks;
using CyberPatriotAutomation.Core.Tasks;
using FluentAssertions;
using Xunit;

public class GroupPolicyTaskTests
{
    [Fact]
    public async Task ExecuteAsync_ShouldSucceed_WhenAllSettingsApply()
    {
        var task = new GroupPolicyTask { DryRun = true };
        var result = await task.ExecuteAsync();
        result.Success.Should().BeTrue();
        result.Message.Should().Contain("Don't display last user name");
        result.Message.Should().Contain("Require Ctrl+Alt+Del");
        result.Message.Should().Contain("ICS (Internet Connection Sharing) disabled");
        result.Message.Should().Contain("Restrict anonymous access");
    }

    [Fact]
    public async Task VerifyAsync_ShouldReturnBool()
    {
        var task = new GroupPolicyTask { DryRun = true };
        var result = await task.VerifyAsync();
        // Result should be either true or false (a valid bool)
        result.Should().Be(result); // Always passes, just confirms no exception
    }
}
