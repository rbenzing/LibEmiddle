using System;
using System.Threading;
using System.Threading.Tasks;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;
using LibEmiddle.Infrastructure;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LibEmiddle.Tests.Unit;

[TestClass]
public class ResilienceManagerTests
{
    private static ResilienceOptions MakeOptions(
        int maxRetries = 2,
        int failureThreshold = 3,
        int minimumThroughput = 1,
        bool enableJitter = false) => new()
    {
        RetryPolicy = new RetryPolicy
        {
            MaxRetries = maxRetries,
            BaseDelay = TimeSpan.FromMilliseconds(5),
            MaxDelay = TimeSpan.FromMilliseconds(50),
            BackoffMultiplier = 2.0,
            UseExponentialBackoff = true
        },
        CircuitBreakerPolicy = new CircuitBreakerPolicy
        {
            FailureThreshold = failureThreshold,
            RecoveryTimeout = TimeSpan.FromMilliseconds(200),
            MinimumThroughput = minimumThroughput,
            SamplingPeriod = TimeSpan.FromSeconds(10)
        },
        TimeoutPolicy = new TimeoutPolicy
        {
            DefaultTimeout = TimeSpan.FromSeconds(5),
            ConnectionTimeout = TimeSpan.FromSeconds(5),
            SendTimeout = TimeSpan.FromSeconds(5),
            ReceiveTimeout = TimeSpan.FromSeconds(5)
        },
        EnableJitter = enableJitter
    };

    [TestMethod]
    public async Task ExecuteAsync_SuccessOnFirstAttempt_ReturnsResult()
    {
        using var mgr = new ResilienceManager(MakeOptions());
        int result = await mgr.ExecuteAsync(
            _ => Task.FromResult(42),
            ResilienceOperationType.MessageSend);
        Assert.AreEqual(42, result);
    }

    [TestMethod]
    public async Task ExecuteAsync_TransientFailure_RetriesAndSucceeds()
    {
        using var mgr = new ResilienceManager(MakeOptions());
        int attempts = 0;
        int result = await mgr.ExecuteAsync<int>(ct =>
        {
            attempts++;
            if (attempts < 2) throw new InvalidOperationException("transient");
            return Task.FromResult(99);
        }, ResilienceOperationType.MessageSend);

        Assert.AreEqual(99, result);
        Assert.AreEqual(2, attempts);
    }

    [TestMethod]
    public async Task ExecuteAsync_ExceedsRetries_ThrowsOriginalException()
    {
        using var mgr = new ResilienceManager(MakeOptions(maxRetries: 1));
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => mgr.ExecuteAsync<int>(
                _ => throw new InvalidOperationException("permanent"),
                ResilienceOperationType.MessageSend));
    }

    [TestMethod]
    public async Task ExecuteAsync_CircuitOpensAfterThreshold_ThrowsWhenOpen()
    {
        using var mgr = new ResilienceManager(MakeOptions(maxRetries: 0, failureThreshold: 2, minimumThroughput: 1));

        // Two operations fail to trip the circuit (threshold=2, retries=0)
        for (int i = 0; i < 2; i++)
        {
            try { await mgr.ExecuteAsync<int>(_ => throw new InvalidOperationException("fail"), ResilienceOperationType.MessageSend); }
            catch { }
        }

        var stats = await mgr.GetStatisticsAsync(ResilienceOperationType.MessageSend);
        Assert.AreEqual(CircuitBreakerState.Open, stats.CircuitBreakerState);

        // Next call should be rejected immediately by the open circuit
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => mgr.ExecuteAsync<int>(_ => Task.FromResult(0), ResilienceOperationType.MessageSend));
    }

    [TestMethod]
    public async Task GetStatisticsAsync_AfterMixedRuns_ReportsCorrectCounts()
    {
        using var mgr = new ResilienceManager(MakeOptions());
        await mgr.ExecuteAsync(_ => Task.FromResult(1), ResilienceOperationType.KeyExchange);
        try { await mgr.ExecuteAsync<int>(_ => throw new Exception("e"), ResilienceOperationType.KeyExchange); } catch { }

        var stats = await mgr.GetStatisticsAsync(ResilienceOperationType.KeyExchange);
        Assert.IsTrue(stats.TotalExecutions >= 2);
        Assert.IsTrue(stats.SuccessfulExecutions >= 1);
        Assert.IsTrue(stats.FailedExecutions >= 1);
    }
}
