// =============================================================================
// PinnacleCyPat - Local account helper tests
// =============================================================================

using PinnacleCyPat.Core;
using PinnacleCyPat.Core.Models;
using PinnacleCyPat.Core.Utilities;
using FluentAssertions;
using Xunit;

namespace PinnacleCyPat.Tests;

public class LocalAccountsTests
{
    /// <summary>
    /// Real `net localgroup Administrators` output: a header, a comment
    /// mentioning "Administrators", a dashed separator, the members, and a
    /// trailing status sentence.
    /// </summary>
    private const string NetLocalGroupOutput =
        "Alias name     Administrators\r\n"
        + "Comment        Administrators have complete and unrestricted access to the computer/domain\r\n"
        + "\r\n"
        + "Members\r\n"
        + "\r\n"
        + "-------------------------------------------------------------------------------\r\n"
        + "Administrator\r\n"
        + "CYBERPC\\alice\r\n"
        + "bob\r\n"
        + "The command completed successfully.\r\n";

    [Fact]
    public void ParseGroupMembers_ShouldReadOnlyTheMemberRows()
    {
        LocalAccounts
            .ParseGroupMembers(NetLocalGroupOutput)
            .Should()
            .Equal("Administrator", "CYBERPC\\alice", "bob");
    }

    [Fact]
    public void IsGroupMember_ShouldMatchExactNamesCaseInsensitively()
    {
        var members = LocalAccounts.ParseGroupMembers(NetLocalGroupOutput);

        LocalAccounts.IsGroupMember(members, "bob").Should().BeTrue();
        LocalAccounts.IsGroupMember(members, "BOB").Should().BeTrue();
        LocalAccounts.IsGroupMember(members, "Administrator").Should().BeTrue();
        // DOMAIN\user entries match on the bare account name too.
        LocalAccounts.IsGroupMember(members, "alice").Should().BeTrue();
    }

    [Theory]
    [InlineData("admin")] // appears inside "Administrators" in the header
    [InlineData("command")] // appears in "The command completed successfully."
    [InlineData("access")] // appears in the comment line
    [InlineData("the")]
    [InlineData("comp")]
    public void IsGroupMember_ShouldNotMatchSurroundingProse(string impostor)
    {
        // The old check substring-searched the whole blob, so each of these was
        // wrongly treated as an administrator.
        var members = LocalAccounts.ParseGroupMembers(NetLocalGroupOutput);
        LocalAccounts.IsGroupMember(members, impostor).Should().BeFalse();
    }

    [Fact]
    public void GeneratePassword_ShouldBeUniquePerAccount()
    {
        // Cycling the fixed list alone repeated passwords once there were more
        // accounts than entries.
        var count = AppConfig.SecurePasswords.Length * 2;
        var generated = Enumerable.Range(0, count).Select(LocalAccounts.GeneratePassword).ToList();

        generated.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void GeneratePassword_ShouldMeetComplexityRequirements()
    {
        foreach (var password in Enumerable.Range(0, 12).Select(LocalAccounts.GeneratePassword))
        {
            password.Length.Should().BeGreaterThanOrEqualTo(12);
            password.Should().Match(p => p.Any(char.IsUpper));
            password.Should().Match(p => p.Any(char.IsLower));
            password.Should().Match(p => p.Any(char.IsDigit));
            password.Should().Match(p => p.Any(c => !char.IsLetterOrDigit(c)));
        }
    }

    [Fact]
    public void PrimaryUsers_ShouldCollectTheAutoLoginAccount()
    {
        // READMEs warn that changing the primary auto-login password can lock you
        // out of the machine, so it must be identifiable.
        var readme = new ReadmeData();
        readme.Administrators.Add(new AuthorizedUser { Username = "twellick", IsPrimaryUser = true });
        readme.Administrators.Add(new AuthorizedUser { Username = "jplofe" });
        readme.Users.Add(new AuthorizedUser { Username = "pprice" });

        var primary = LocalAccounts.PrimaryUsers(readme);

        primary.Should().ContainSingle().Which.Should().Be("twellick");
        primary.Contains("TWELLICK").Should().BeTrue("matching is case-insensitive");
        primary.Should().NotContain("jplofe");
    }

    [Fact]
    public void PrimaryUsers_ShouldBeEmptyWithoutReadmeData()
    {
        LocalAccounts.PrimaryUsers(null).Should().BeEmpty();
    }
}
