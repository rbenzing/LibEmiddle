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
    #region State Management and Serialization

    public async Task<string> GetSerializedStateAsync()
    {
        ThrowIfDisposed();

        await _sessionLock.WaitAsync();
        try
        {
            var keyState = new GroupKeyState
            {
                GroupId = _groupId,
                LastRotationTimestamp = _lastRotationTimestamp,
                SenderState = new GroupSenderStateDto
                {
                    ChainKey = Convert.ToBase64String(_currentChainKey),
                    Iteration = _currentIteration,
                    CreationTimestamp = _lastRotationTimestamp
                },
                ReceiverStates = _senderKeys.ToDictionary(
                    kvp => kvp.Key,
                    kvp => Convert.ToBase64String(kvp.Value.ChainKey))
            };

            var sessionState = new GroupSessionState
            {
                SessionId = SessionId,
                GroupId = _groupId,
                State = State,
                CreatedAt = CreatedAt,
                RotationStrategy = RotationStrategy,
                KeyState = keyState,
                GroupInfo = _groupInfo
            };

            return JsonSerialization.Serialize(sessionState);
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    public async Task<bool> RestoreSerializedStateAsync(string serializedState)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrEmpty(serializedState);

        await _sessionLock.WaitAsync();
        try
        {
            var sessionState = JsonSerialization.Deserialize<GroupSessionState>(serializedState);
            if (sessionState?.GroupId != _groupId)
                return false;

            // Restore key state
            if (sessionState.KeyState?.SenderState != null)
            {
                _currentChainKey = Convert.FromBase64String(sessionState.KeyState.SenderState.ChainKey);
                _currentIteration = sessionState.KeyState.SenderState.Iteration;
                _lastRotationTimestamp = sessionState.KeyState.LastRotationTimestamp;

                // Restore receiver states
                foreach (var kvp in sessionState.KeyState.ReceiverStates)
                {
                    _senderKeys[kvp.Key] = new GroupSenderState
                    {
                        ChainKey = Convert.FromBase64String(kvp.Value),
                        Iteration = 0, // Default to 0 for backward compatibility
                        CreationTimestamp = sessionState.KeyState.LastRotationTimestamp
                    };
                }
            }

            // Restore session state
            State = sessionState.State;
            RotationStrategy = sessionState.RotationStrategy;

            // Restore group info and members
            if (sessionState.GroupInfo != null)
            {
                _groupInfo = sessionState.GroupInfo;

                foreach (var member in sessionState.GroupInfo.Members)
                {
                    _members[member.Key] = member.Value;
                }

                foreach (var removed in sessionState.GroupInfo.RemovedMembers)
                {
                    _removedMembers[removed.Key] = removed.Value;
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            LoggingManager.LogError(nameof(GroupSession), $"Failed to restore session state: {ex.Message}");
            return false;
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    #endregion
}
