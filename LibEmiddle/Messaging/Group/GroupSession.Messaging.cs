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
    #region Message Encryption/Decryption

    public async Task<EncryptedGroupMessage?> EncryptMessageAsync(string message)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrEmpty(message);

        await _sessionLock.WaitAsync();
        try
        {
            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot encrypt: Session is terminated.");
            if (State == SessionState.Suspended)
                throw new InvalidOperationException("Cannot encrypt: Session is suspended.");

            // Auto-activate if needed
            if (State == SessionState.Initialized)
            {
                State = SessionState.Active;
                OnStateChanged(SessionState.Initialized, State);
            }

            // Check permissions
            if (!HasPermission(GroupOperation.Send))
                throw new UnauthorizedAccessException("You don't have permission to send messages in this group.");

            // Check if key rotation is needed
            await CheckAndRotateKeyIfNeededAsync();

            // Ensure we have a chain key
            if (_currentChainKey.Length == 0)
            {
                _currentChainKey = Sodium.GenerateRandomBytes(Constants.CHAIN_KEY_SIZE);
                _currentIteration = 0;
            }

            // Derive message key and advance chain
            byte[] messageKey = Sodium.DeriveMessageKey(_currentChainKey);
            _currentChainKey = Sodium.AdvanceChainKey(_currentChainKey);
            uint messageIteration = _currentIteration++;

            try
            {
                // Encrypt the message using AES
                byte[] plaintext = Encoding.UTF8.GetBytes(message);
                byte[] nonce = Sodium.GenerateRandomBytes(Constants.NONCE_SIZE);
                byte[] associatedData = Encoding.UTF8.GetBytes($"{_groupId}:{_lastRotationTimestamp}");
                byte[] ciphertext = AES.AESEncrypt(plaintext, messageKey, nonce, associatedData);

                var encryptedMessage = new EncryptedGroupMessage
                {
                    GroupId = _groupId,
                    SenderIdentityKey = _identityKeyPair.PublicKey,
                    Ciphertext = ciphertext,
                    Nonce = nonce,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    RotationEpoch = _lastRotationTimestamp,
                    MessageId = $"iter:{messageIteration}:{Guid.NewGuid():N}"
                };

                // Sign the message
                byte[] dataToSign = GetMessageDataToSign(encryptedMessage);
                encryptedMessage.Signature = Sodium.SignDetached(dataToSign, _identityKeyPair.PrivateKey);

                return encryptedMessage;
            }
            finally
            {
                SecureMemory.SecureClear(messageKey);
            }
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    public async Task<string?> DecryptMessageAsync(EncryptedGroupMessage encryptedMessage)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(encryptedMessage);

        if (encryptedMessage.GroupId != _groupId)
            throw new ArgumentException($"Message is for group {encryptedMessage.GroupId}, but this session is for group {_groupId}");

        await _sessionLock.WaitAsync();
        try
        {
            // Validate message
            if (!ValidateGroupMessage(encryptedMessage))
                return null;

            if (State == SessionState.Terminated)
                throw new InvalidOperationException("Cannot decrypt: Session is terminated.");

            // Auto-activate if needed
            if (State == SessionState.Initialized)
            {
                State = SessionState.Active;
                OnStateChanged(SessionState.Initialized, State);
            }

            // Check membership and timing
            if (!IsMember(_identityKeyPair.PublicKey))
                return null;

            if (WasRemovedBeforeTimestamp(_identityKeyPair.PublicKey, encryptedMessage.Timestamp))
                return null;

            // Get sender key state
            string senderId = GetMemberId(encryptedMessage.SenderIdentityKey);
            if (!_senderKeys.TryGetValue(senderId, out GroupSenderState? senderKeyState))
                return null;

            // Extract iteration number from message ID to advance chain key to correct state
            long? messageIteration = ExtractSequenceFromMessageId(encryptedMessage.MessageId);
            byte[] currentChainKey = senderKeyState.ChainKey.ToArray();

            try
            {
                // If we have an iteration number, advance the chain key from the distribution iteration to the message iteration
                if (messageIteration.HasValue)
                {
                    // Calculate how many steps to advance from the distribution iteration to the message iteration
                    long stepsToAdvance = messageIteration.Value - senderKeyState.Iteration;
                    for (long i = 0; i < stepsToAdvance; i++)
                    {
                        byte[] nextChainKey = Sodium.AdvanceChainKey(currentChainKey);
                        SecureMemory.SecureClear(currentChainKey);
                        currentChainKey = nextChainKey;
                    }
                }

                // Derive message key from the correctly advanced chain key
                byte[] messageKey = Sodium.DeriveMessageKey(currentChainKey);

                try
                {
                    // Decrypt the message
                    byte[] associatedData = Encoding.UTF8.GetBytes($"{_groupId}:{encryptedMessage.RotationEpoch}");
                    byte[] decrypted = AES.AESDecrypt(
                        encryptedMessage.Ciphertext,
                        messageKey,
                        encryptedMessage.Nonce,
                        associatedData);

                    string plaintext = Encoding.UTF8.GetString(decrypted);

                    // Register the message as seen ONLY after successful decryption so that a
                    // transient decryption failure does not permanently block a legitimate retry.
                    RecordMessageSeen(encryptedMessage);

                    return plaintext;
                }
                finally
                {
                    SecureMemory.SecureClear(messageKey);
                }
            }
            catch
            {
                return null;
            }
            finally
            {
                // Clean up the advanced chain key
                if (currentChainKey != senderKeyState.ChainKey)
                {
                    SecureMemory.SecureClear(currentChainKey);
                }
            }
        }
        finally
        {
            _sessionLock.Release();
        }
    }

    #endregion
}
