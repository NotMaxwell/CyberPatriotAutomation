// =============================================================================
// CyberPatriot Automation Tool - Model Tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

using CyberPatriotAutomation.Core.Models;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

/// <summary>
/// Unit tests for model classes
/// </summary>
public class ModelsTests
{
    #region TaskResult Tests

    [Fact]
    public void TaskResult_ShouldSetExecutedAtOnCreation()
    {
        var result = new TaskResult();

        result.ExecutedAt.Should().BeCloseTo(DateTime.Now, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void TaskResult_ShouldStoreExecutionResult()
    {
        var result = new TaskResult
        {
            TaskName = "Test Task",
            Success = true,
            Message = "Completed",
            ErrorDetails = null
        };

        result.TaskName.Should().Be("Test Task");
        result.Success.Should().BeTrue();
        result.Message.Should().Be("Completed");
    }

    #endregion

    #region ReadmeData Tests

    [Fact]
    public void ReadmeData_ShouldInitializeWithEmptyCollections()
    {
        var data = new ReadmeData();

        data.Administrators.Should().NotBeNull();
        data.Users.Should().NotBeNull();
        data.ProhibitedSoftware.Should().NotBeNull();
        data.CriticalServices.Should().NotBeNull();
    }

    #endregion

    #region AuthorizedUser Tests

    [Fact]
    public void AuthorizedUser_ShouldStoreUserData()
    {
        var user = new AuthorizedUser
        {
            Username = "testuser",
            IsAdmin = true,
            Password = "SecurePass123!"
        };

        user.Username.Should().Be("testuser");
        user.IsAdmin.Should().BeTrue();
        user.Password.Should().Be("SecurePass123!");
    }

    #endregion

    #region SoftwareRequirement Tests

    [Fact]
    public void SoftwareRequirement_ShouldStoreRequirements()
    {
        var software = new SoftwareRequirement
        {
            Name = "Firefox",
            Version = "latest",
            ShouldBeLatest = true
        };

        software.Name.Should().Be("Firefox");
        software.Version.Should().Be("latest");
        software.ShouldBeLatest.Should().BeTrue();
    }

    #endregion

    #region GroupRequirement Tests

    [Fact]
    public void GroupRequirement_ShouldStoreMembersList()
    {
        var group = new GroupRequirement
        {
            GroupName = "Administrators",
            Members = new List<string> { "admin", "user1" }
        };

        group.GroupName.Should().Be("Administrators");
        group.Members.Should().HaveCount(2);
        group.Members.Should().Contain("admin");
    }

    #endregion

    #region ActionableItem Tests

    [Fact]
    public void ActionableItem_ShouldStoreActionDetails()
    {
        var item = new ActionableItem
        {
            Type = ActionableItemType.CreateGroup,
            Description = "Create backup operators group",
            RawText = "Create a group called BackupOperators"
        };

        item.Type.Should().Be(ActionableItemType.CreateGroup);
        item.Description.Should().Contain("backup");
    }

    [Fact]
    public void ActionableItemType_ShouldHaveAllExpectedTypes()
    {
        var types = Enum.GetValues<ActionableItemType>();

        types.Should().Contain(ActionableItemType.CreateGroup);
        types.Should().Contain(ActionableItemType.CreateUser);
        types.Should().Contain(ActionableItemType.DisableService);
    }

    #endregion
}
