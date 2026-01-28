// =============================================================================
// CyberPatriot Automation Tool - Unit Tests
// Author: Maxwell McCormick
// Copyright (c) 2026 Maxwell McCormick. All Rights Reserved.
// =============================================================================

using CyberPatriotAutomation.Core.Tasks;
using CyberPatriotAutomation.Core.Models;
using FluentAssertions;
using Xunit;

namespace CyberPatriotAutomation.Tests;

/// <summary>
/// Unit tests for all security tasks
/// </summary>
public class TasksTests
{
    #region Password Policy Task Tests

    [Fact]
    public void PasswordPolicyTask_ShouldHaveCorrectNameAndDescription()
    {
        var task = new PasswordPolicyTask();

        task.Name.Should().NotBeNullOrEmpty();
        task.Description.Should().NotBeNullOrEmpty();
        task.Name.Should().Contain("Password");
    }

    [Fact]
    public async Task PasswordPolicyTask_ReadSystemStateAsync_ShouldReturnSystemInfo()
    {
        var task = new PasswordPolicyTask();

        var result = await task.ReadSystemStateAsync();

        result.Should().NotBeNull();
    }

    #endregion

    #region Account Permissions Task Tests

    [Fact]
    public void AccountPermissionsTask_ShouldHaveCorrectNameAndDescription()
    {
        var task = new AccountPermissionsTask();

        task.Name.Should().NotBeNullOrEmpty();
        task.Description.Should().NotBeNullOrEmpty();
        task.Name.Should().Contain("Account");
    }

    [Fact]
    public async Task AccountPermissionsTask_ReadSystemStateAsync_ShouldReturnSystemInfo()
    {
        var task = new AccountPermissionsTask();

        var result = await task.ReadSystemStateAsync();

        result.Should().NotBeNull();
    }

    #endregion

    #region User Management Task Tests

    [Fact]
    public void UserManagementTask_ShouldHaveCorrectNameAndDescription()
    {
        var task = new UserManagementTask();

        task.Name.Should().NotBeNullOrEmpty();
        task.Description.Should().NotBeNullOrEmpty();
        task.Name.Should().Contain("User");
    }

    [Fact]
    public void UserManagementTask_SetReadmeData_ShouldAcceptData()
    {
        var task = new UserManagementTask();
        var readmeData = new ReadmeData { Title = "Test README" };

        Action act = () => task.SetReadmeData(readmeData);

        act.Should().NotThrow();
    }

    [Fact]
    public async Task UserManagementTask_ExecuteAsync_WithoutReadmeData_ShouldReturnFailure()
    {
        var task = new UserManagementTask();

        var result = await task.ExecuteAsync();

        result.Should().NotBeNull();
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("README");
    }

    #endregion

    #region Service Management Task Tests

    [Fact]
    public void ServiceManagementTask_ShouldHaveCorrectNameAndDescription()
    {
        var task = new ServiceManagementTask();

        task.Name.Should().NotBeNullOrEmpty();
        task.Description.Should().NotBeNullOrEmpty();
        task.Name.Should().Contain("Service");
    }

    [Fact]
    public void ServiceManagementTask_SetReadmeData_ShouldAcceptData()
    {
        var task = new ServiceManagementTask();
        var readmeData = new ReadmeData { Title = "Test README" };

        Action act = () => task.SetReadmeData(readmeData);

        act.Should().NotThrow();
    }

    [Fact]
    public async Task ServiceManagementTask_ReadSystemStateAsync_ShouldReturnSystemInfo()
    {
        var task = new ServiceManagementTask();

        var result = await task.ReadSystemStateAsync();

        result.Should().NotBeNull();
    }

    #endregion

    #region Audit Policy Task Tests

    [Fact]
    public void AuditPolicyTask_ShouldHaveCorrectNameAndDescription()
    {
        var task = new AuditPolicyTask();

        task.Name.Should().NotBeNullOrEmpty();
        task.Description.Should().NotBeNullOrEmpty();
        task.Name.Should().Contain("Audit");
    }

    [Fact]
    public async Task AuditPolicyTask_ReadSystemStateAsync_ShouldReturnSystemInfo()
    {
        var task = new AuditPolicyTask();

        var result = await task.ReadSystemStateAsync();

        result.Should().NotBeNull();
    }

    #endregion

    #region Firewall Configuration Task Tests

    [Fact]
    public void FirewallConfigurationTask_ShouldHaveCorrectNameAndDescription()
    {
        var task = new FirewallConfigurationTask();

        task.Name.Should().Be("Firewall Configuration");
        task.Description.Should().Contain("Firewall");
    }

    [Fact]
    public async Task FirewallConfigurationTask_ReadSystemStateAsync_ShouldNotThrow()
    {
        var task = new FirewallConfigurationTask();

        Func<Task> act = async () => await task.ReadSystemStateAsync();

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task FirewallConfigurationTask_ExecuteAsync_ShouldReturnTaskResult()
    {
        var task = new FirewallConfigurationTask();

        var result = await task.ExecuteAsync();

        result.Should().NotBeNull();
        result.TaskName.Should().Be("Firewall Configuration");
    }

    #endregion

    #region Security Hardening Task Tests

    [Fact]
    public void SecurityHardeningTask_ShouldHaveCorrectNameAndDescription()
    {
        var task = new SecurityHardeningTask();

        task.Name.Should().Be("Security Hardening");
        task.Description.Should().Contain("security");
    }

    [Fact]
    public async Task SecurityHardeningTask_ReadSystemStateAsync_ShouldNotThrow()
    {
        var task = new SecurityHardeningTask();

        Func<Task> act = async () => await task.ReadSystemStateAsync();

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task SecurityHardeningTask_ExecuteAsync_ShouldReturnTaskResult()
    {
        var task = new SecurityHardeningTask();

        var result = await task.ExecuteAsync();

        result.Should().NotBeNull();
        result.TaskName.Should().Be("Security Hardening");
    }

    #endregion

    #region Prohibited Media Task Tests

    [Fact]
    public void ProhibitedMediaTask_ShouldHaveCorrectNameAndDescription()
    {
        var task = new ProhibitedMediaTask();

        task.Name.Should().Be("Prohibited Media Scanner");
        task.Description.Should().Contain("prohibited");
    }

    [Fact]
    public void ProhibitedMediaTask_SetReadmeData_ShouldNotThrow()
    {
        var task = new ProhibitedMediaTask();
        var readmeData = new ReadmeData
        {
            Title = "Test README",
            ProhibitedSoftware = new List<string> { "game.exe" }
        };

        Action act = () => task.SetReadmeData(readmeData);

        act.Should().NotThrow();
    }

    [Fact]
    public async Task ProhibitedMediaTask_ReadSystemStateAsync_ShouldNotThrow()
    {
        var task = new ProhibitedMediaTask();

        Func<Task> act = async () => await task.ReadSystemStateAsync();

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task ProhibitedMediaTask_ExecuteAsync_ShouldReturnTaskResult()
    {
        var task = new ProhibitedMediaTask();

        var result = await task.ExecuteAsync();

        result.Should().NotBeNull();
        result.TaskName.Should().Be("Prohibited Media Scanner");
    }

    #endregion
}
