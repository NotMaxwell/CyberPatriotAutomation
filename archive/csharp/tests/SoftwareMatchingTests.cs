// =============================================================================
// PinnacleCyPat - Software matching and uninstall-command tests
// Author: Maxwell McCormick
// Copyright 2026 Maxwell McCormick. Licensed under Apache-2.0.
// =============================================================================
using FluentAssertions;
using PinnacleCyPat.Core.Tasks;
using PinnacleCyPat.Core.Utilities;
using Xunit;

namespace PinnacleCyPat.Tests;

/// <summary>
/// The software task failed in the field: CCleaner, Python and Jellyfin were not
/// removed, and Chrome and Notepad++ were not updated. Each case here pins one
/// of the reasons.
/// </summary>
/// <remarks>
/// The display names used are the ones Windows actually registers, suffixes and
/// all. Testing against tidy names like "Notepad++" is what let the original
/// exact-match lookup look correct.
/// </remarks>
public class SoftwareMatchingTests
{
    [Theory]
    [InlineData("CCleaner", "CCleaner")]
    [InlineData("Python 3.12.1 (64-bit)", "Python")]
    [InlineData("Python Launcher", "Python")]
    [InlineData("Jellyfin Media Player", "Jellyfin")]
    [InlineData("Jellyfin Media Player 1.9.1", "Jellyfin")]
    [InlineData("CCleaner Free 6.21", "CCleaner")]
    public void ProhibitedSoftwareIsMatchedThroughItsRegisteredName(string installed, string term)
    {
        PackageMatching.Matches(installed, term).Should().BeTrue();
    }

    [Theory]
    [InlineData("Google Chrome", "Firefox")]
    [InlineData("Notepad++ (64-bit x64)", "Python")]
    public void UnrelatedSoftwareIsNotMatched(string installed, string term)
    {
        PackageMatching.Matches(installed, term).Should().BeFalse();
    }

    /// <summary>
    /// The update bug: display names carry suffixes, so an exact dictionary
    /// lookup matched almost nothing.
    /// </summary>
    [Theory]
    [InlineData("Notepad++ (64-bit x64)", "notepadplusplus.install")]
    [InlineData("Google Chrome", "googlechrome")]
    [InlineData("Mozilla Firefox (x64 en-US)", "firefox")]
    [InlineData("7-Zip 23.01 (x64)", "7zip.install")]
    [InlineData("VLC media player", "vlc")]
    [InlineData("Wireshark 4.2.0 64-bit", "wireshark")]
    public void InstalledNamesResolveToTheirChocolateyPackage(string installed, string expected)
    {
        PackageMatching
            .ResolvePackageId(installed, SoftwareManagementTask.PackageIds)
            .Should()
            .Be(expected);
    }

    [Fact]
    public void SoftwareWithNoKnownPackageResolvesToNothing()
    {
        PackageMatching
            .ResolvePackageId("Some Bespoke Internal Tool", SoftwareManagementTask.PackageIds)
            .Should()
            .BeNull();
    }

    /// <summary>The longest matching key wins, so a short key cannot shadow it.</summary>
    [Fact]
    public void TheMostSpecificPackageKeyWins()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Firefox"] = "firefox-short",
            ["Mozilla Firefox"] = "firefox-long",
        };
        PackageMatching.ResolvePackageId("Mozilla Firefox (x64 en-US)", map)
            .Should()
            .Be("firefox-long");
    }

    [Theory]
    [InlineData("Notepad++ (64-bit x64)", "notepad++")]
    [InlineData("Python 3.12.1 (64-bit)", "python")]
    [InlineData("7-Zip 23.01 (x64)", "7-zip")]
    [InlineData("Mozilla Firefox (x64 en-US)", "mozilla firefox")]
    public void NormalizeStripsVersionAndArchitectureDecoration(string input, string expected)
    {
        PackageMatching.Normalize(input).Should().Be(expected);
    }

    /// <summary>
    /// The default prohibitions have to survive the README being absent - that
    /// was the whole reason nothing was removed on a run without one.
    /// </summary>
    [Fact]
    public void DefaultProhibitionsApplyWithoutAReadme()
    {
        var task = new SoftwareManagementTask();
        task.ProhibitedSoftware.Should().Contain(["Python", "CCleaner", "Jellyfin"]);
    }

    [Fact]
    public void DefaultProhibitionsSurviveANullReadme()
    {
        var task = new SoftwareManagementTask();
        task.SetReadmeData(null);
        task.ProhibitedSoftware.Should().Contain(["Python", "CCleaner", "Jellyfin"]);
    }

    /// <summary>A README that requires the software still wins over the default.</summary>
    [Fact]
    public void RequiredSoftwareIsNotProhibitedByDefault()
    {
        var task = new SoftwareManagementTask();
        task.SetReadmeData(
            new PinnacleCyPat.Core.Models.ReadmeData
            {
                RequiredSoftware =
                [
                    new PinnacleCyPat.Core.Models.SoftwareRequirement { Name = "Python 3" },
                ],
            }
        );

        task.ProhibitedSoftware.Should().NotContain("Python");
        task.ProhibitedSoftware.Should().Contain(["CCleaner", "Jellyfin"]);
    }
}

/// <summary>
/// Deriving a silent uninstall command from what the registry records.
/// </summary>
/// <remarks>
/// These are the shapes the four programs in the bug report actually register.
/// </remarks>
public class UninstallCommandTests
{
    [Fact]
    public void NsisUninstallersGetTheSilentSwitch()
    {
        // CCleaner, Notepad++ and Jellyfin all ship NSIS uninstallers, and none
        // of them appear in Win32_Product - so `wmic product call uninstall`
        // could never have removed any of them.
        var command = UninstallCommandBuilder.Build(@"C:\Program Files\CCleaner\uninst.exe");

        command.Should().NotBeNull();
        command!.Value.Program.Should().Be(@"C:\Program Files\CCleaner\uninst.exe");
        command.Value.Arguments.Should().Be("/S");
    }

    [Fact]
    public void AQuotedPathWithSpacesIsSplitCorrectly()
    {
        var command = UninstallCommandBuilder.Build(
            "\"C:\\Program Files\\Notepad++\\uninstall.exe\""
        );

        command!.Value.Program.Should().Be(@"C:\Program Files\Notepad++\uninstall.exe");
        command.Value.Arguments.Should().Be("/S");
    }

    [Fact]
    public void InnoUninstallersGetVerySilent()
    {
        var command = UninstallCommandBuilder.Build(@"C:\Program Files\App\unins000.exe");

        command!.Value.Arguments.Should().Contain("/VERYSILENT");
        command.Value.Arguments.Should().Contain("/NORESTART");
    }

    /// <summary>
    /// The registered MSI string uses <c>/I</c>, which is *install* - passing it
    /// through would open the repair dialog rather than remove anything.
    /// </summary>
    [Fact]
    public void MsiUninstallersAreRewrittenToRemove()
    {
        var command = UninstallCommandBuilder.Build(
            "MsiExec.exe /I{90160000-008C-0000-1000-0000000FF1CE}"
        );

        command!.Value.Program.Should().Be("msiexec.exe");
        command.Value.Arguments.Should().Be("/x {90160000-008C-0000-1000-0000000FF1CE} /qn /norestart");
    }

    [Fact]
    public void PythonsBundleUninstallerIsMadeQuiet()
    {
        var command = UninstallCommandBuilder.Build(
            "\"C:\\Users\\u\\AppData\\Local\\Package Cache\\{abc}\\python-3.12.1-amd64.exe\" /uninstall"
        );

        command!.Value.Arguments.Should().Contain("/uninstall");
        command.Value.Arguments.Should().Contain("/quiet");
    }

    /// <summary>A QuietUninstallString is already unattended; leave it alone.</summary>
    [Fact]
    public void AQuietUninstallStringIsUsedVerbatim()
    {
        var command = UninstallCommandBuilder.Build(
            "\"C:\\Program Files\\App\\uninst.exe\" /SILENT /NORESTART",
            alreadySilent: true
        );

        command!.Value.Arguments.Should().Be("/SILENT /NORESTART");
    }

    [Fact]
    public void ASwitchAlreadyPresentIsNotDuplicated()
    {
        var command = UninstallCommandBuilder.Build(@"C:\App\uninst.exe /S");
        command!.Value.Arguments.Should().Be("/S");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AMissingUninstallStringYieldsNothing(string? value)
    {
        UninstallCommandBuilder.Build(value).Should().BeNull();
    }

    [Fact]
    public void AMalformedProductCodeIsRejectedRatherThanPassedToMsiexec()
    {
        // A short code would make msiexec pop an error dialog and wait.
        UninstallCommandBuilder.Build("MsiExec.exe /I{not-a-guid}").Should().BeNull();
    }
}

/// <summary>
/// Regressions found in a real run log, not by reasoning about the code.
/// </summary>
public class SoftwareRunLogRegressionTests
{
    /// <summary>
    /// The updater must never be offered software the run just removed.
    /// </summary>
    /// <remarks>
    /// A real run removed "Python 3.13.0 (64-bit)", then four minutes later ran
    /// <c>choco upgrade python</c> - which installs a package that is absent -
    /// and Python 3.14.7 was present at verification. The candidate list is
    /// built from the inventory read *before* removal, so every removed program
    /// was still in it.
    /// </remarks>
    [Fact]
    public void ProhibitedSoftwareResolvesToAPackageIdThatMustBeExcluded()
    {
        // The mapping itself is correct and has to stay correct - it is what the
        // exclusion is keyed on.
        PackageMatching
            .ResolvePackageId("Python 3.13.0 (64-bit)", SoftwareManagementTask.PackageIds)
            .Should()
            .Be("python");

        PackageMatching
            .ResolvePackageId("Python Launcher", SoftwareManagementTask.PackageIds)
            .Should()
            .Be("python");
    }

    /// <summary>
    /// The display names from the real run resolve to the ids the run logged.
    /// </summary>
    [Theory]
    [InlineData("7-Zip 24.08 (x64)", "7zip.install")]
    [InlineData("Notepad++ (32-bit x86)", "notepadplusplus.install")]
    [InlineData("Wireshark 4.4.1 x64", "wireshark")]
    [InlineData("Google Chrome", "googlechrome")]
    public void RealInstalledNamesResolveAsTheRunLogged(string installed, string expected)
    {
        PackageMatching
            .ResolvePackageId(installed, SoftwareManagementTask.PackageIds)
            .Should()
            .Be(expected);
    }

    /// <summary>
    /// The uninstall strings the real image registered are all usable.
    /// </summary>
    [Fact]
    public void TheUninstallStringsFromTheRealImageAreUsable()
    {
        // Jellyfin and Python register bundles that already carry both switches.
        var jellyfin = UninstallCommandBuilder.Build(
            "\"C:\\ProgramData\\Package Cache\\{dd9e5c35}\\JellyfinMediaPlayer-1.11.1-windows-x64.exe\" /uninstall /quiet"
        );
        jellyfin!.Value.Arguments.Should().Contain("/uninstall").And.Contain("/quiet");

        // Python Launcher registers an MSI with /X - already uninstall, but it
        // still needs /qn or msiexec shows UI.
        var launcher = UninstallCommandBuilder.Build(
            "MsiExec.exe /X{1F3BC6BD-2010-40E7-85B2-F1A5E2EB5FF2}"
        );
        launcher!.Value.Program.Should().Be("msiexec.exe");
        launcher.Value.Arguments.Should().Be("/x {1F3BC6BD-2010-40E7-85B2-F1A5E2EB5FF2} /qn /norestart");
    }
}
