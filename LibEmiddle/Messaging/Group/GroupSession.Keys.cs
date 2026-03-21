using System.Collections.Concurrent;
using System.Text;
using LibEmiddle.Abstractions;
using LibEmiddle.Core;
using LibEmiddle.Crypto;
using LibEmiddle.Domain;
using LibEmiddle.Domain.Enums;

namespace LibEmiddle.Messaging.Group;

public sealed partial class GroupSession
{
    #region Key Management

    public async Task<bool> RotateKeyAsync()
    {
        ThrowIfDisposed();

        await _sessionLock.WaitAsync();
        try
        {
            return await RotateKeyInternalAsync();
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    private Task<bool> RotateKeyInternalAsync()
    {
        if (State == SessionState.Terminated)
            throw new InvalidOperationException("Cannot rotate key: Session is terminated.");

        if (!HasPermission(GroupOperation.RotateKey))
            throw new UnauthorizedAccessException("You don't have permission to rotate the group key.");

        // Prevent infinite recursion
        if (_isRotating)
            return Task.FromResult(false);

        try
        {
            _isRotating = true;

            // Generate new chain key
            byte[] newChainKey = Sodium.GenerateRandomBytes(Constants.CHAIN_KEY_SIZE);

            // Clear old key securely
            SecureMemory.SecureClear(_currentChainKey);

            // Update state
            _currentChainKey = newChainKey;
            _currentIteration = 0;
            _lastRotationTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // Clear old sender keys
            foreach (var senderState in _senderKeys.Values)
            {
                SecureMemory.SecureClear(senderState.ChainKey);
            }
            _senderKeys.Clear();

            // Create and process distribution message
            var distribution = CreateDistributionMessage();
            ProcessDistributionMessage(distribution);

            return Task.FromResult(true);
        }
        finally
        {
            _isRotating = false;
        }
    }

    public SenderKeyDistributionMessage CreateDistributionMessage()
    {
        ThrowIfDisposed();

        // Ensure chain key is initialized
        if (_currentChainKey.Length == 0)
            throw new InvalidOperationException("Cannot create distribution message: Session chain key is not initialized. Call ActivateAsync() first.");

        var distribution = new SenderKeyDistributionMessage
        {
            GroupId = _groupId,
            ChainKey = _currentChainKey.ToArray(),
            Iteration = _currentIteration,
            SenderIdentityKey = _identityKeyPair.PublicKey,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
        };

        // Sign the distribution message
        byte[] dataToSign = GetDistributionDataToSign(distribution);
        distribution.Signature = Sodium.SignDetached(dataToSign, _identityKeyPair.PrivateKey);

        return distribution;
    }

    public bool ProcessDistributionMessage(SenderKeyDistributionMessage distribution)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(distribution);

        if (distribution.GroupId != _groupId)
            return false;

        if (distribution.SenderIdentityKey == null || distribution.ChainKey == null)
            return false;

        // Validate signature
        if (distribution.Signature != null)
        {
            byte[] dataToSign = GetDistributionDataToSign(distribution);
            if (!Sodium.SignVerifyDetached(distribution.Signature, dataToSign, distribution.SenderIdentityKey))
                return false;
        }

        // Check if sender is a member
        string senderId = GetMemberId(distribution.SenderIdentityKey);
        if (!_members.ContainsKey(senderId))
            return false;

        // Store the sender key state
        if (distribution.ChainKey == null || distribution.ChainKey.Length != Constants.CHAIN_KEY_SIZE)
        {
            LoggingManager.LogError(nameof(GroupSession), $"Invalid chain key length for sender {senderId}: expected {Constants.CHAIN_KEY_SIZE}, got {distribution.ChainKey?.Length ?? 0}");
            return false;
        }
        _senderKeys[senderId] = new GroupSenderState
        {
            ChainKey = distribution.ChainKey.ToArray(),
            Iteration = distribution.Iteration,
            CreationTimestamp = distribution.Timestamp
        };

        // A new distribution message establishes a fresh key epoch for this sender.
        // Reset replay-protection state so that messages in the new epoch (which start
        // iteration counting from zero again) are not incorrectly rejected.
        _lastSeenSequence.TryRemove(senderId, out _);
        _seenMessageIds.TryRemove(senderId, out _);

        // Record join time if not already recorded
        RecordJoinTime(distribution.SenderIdentityKey);

        return true;
    }

    #endregion
}
