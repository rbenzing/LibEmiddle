using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using E2EELibrary.Models;

namespace E2EELibraryTests
{
    [TestClass]
    public class MessageDeserializationTests
    {
        [TestMethod]
        public void EncryptedMessage_FromDictionary_ValidInput_ShouldDeserializeCorrectly()
        {
            // Arrange
            var guid = Guid.NewGuid();
            var messageDict = new Dictionary<string, object>
            {
                ["ciphertext"] = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }),
                ["nonce"] = Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }),
                ["messageNumber"] = 42,
                ["senderDHKey"] = Convert.ToBase64String(new byte[] { 9, 10, 11, 12 }),
                ["timestamp"] = 1634567890123L,
                ["messageId"] = guid.ToString(),
                ["sessionId"] = "test-session-123"
            };

            // Act
            var message = EncryptedMessage.FromDictionary(messageDict);

            // Assert
            Assert.IsNotNull(message);
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4 }, message.Ciphertext);
            CollectionAssert.AreEqual(new byte[] { 5, 6, 7, 8 }, message.Nonce);
            Assert.AreEqual(42, message.MessageNumber);
            CollectionAssert.AreEqual(new byte[] { 9, 10, 11, 12 }, message.SenderDHKey);
            Assert.AreEqual(1634567890123L, message.Timestamp);
            Assert.AreEqual(guid, message.MessageId);
            Assert.AreEqual("test-session-123", message.SessionId);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptedMessage_FromDictionary_NullDictionary_ShouldThrowException()
        {
            // Act & Assert - should throw ArgumentNullException
            EncryptedMessage.FromDictionary(null);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void EncryptedMessage_FromDictionary_MissingRequiredField_ShouldThrowException()
        {
            // Arrange - Missing required senderDHKey
            var messageDict = new Dictionary<string, object>
            {
                ["ciphertext"] = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }),
                ["nonce"] = Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }),
                ["messageNumber"] = 42
                // senderDHKey is missing
            };

            // Act & Assert - should throw FormatException
            EncryptedMessage.FromDictionary(messageDict);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void EncryptedMessage_FromDictionary_InvalidBase64_ShouldThrowException()
        {
            // Arrange - Invalid Base64 string
            var messageDict = new Dictionary<string, object>
            {
                ["ciphertext"] = "Not a valid Base64 string!!!",
                ["nonce"] = Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }),
                ["messageNumber"] = 42,
                ["senderDHKey"] = Convert.ToBase64String(new byte[] { 9, 10, 11, 12 })
            };

            // Act & Assert - should throw FormatException
            EncryptedMessage.FromDictionary(messageDict);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void EncryptedMessage_FromDictionary_InvalidMessageNumber_ShouldThrowException()
        {
            // Arrange - Non-integer message number
            var messageDict = new Dictionary<string, object>
            {
                ["ciphertext"] = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }),
                ["nonce"] = Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }),
                ["messageNumber"] = "not a number",
                ["senderDHKey"] = Convert.ToBase64String(new byte[] { 9, 10, 11, 12 })
            };

            // Act & Assert - should throw FormatException
            EncryptedMessage.FromDictionary(messageDict);
        }

        [TestMethod]
        public void EncryptedMessage_FromDictionary_OptionalFields_ShouldSetDefaults()
        {
            // Arrange - Only required fields
            var messageDict = new Dictionary<string, object>
            {
                ["ciphertext"] = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }),
                ["nonce"] = Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }),
                ["messageNumber"] = 42,
                ["senderDHKey"] = Convert.ToBase64String(new byte[] { 9, 10, 11, 12 })
                // timestamp and messageId are missing
            };

            // Act
            var message = EncryptedMessage.FromDictionary(messageDict);

            // Assert
            Assert.IsNotNull(message);
            Assert.AreEqual(0, message.Timestamp); // Default value
            Assert.AreEqual(Guid.Empty, message.MessageId); // Default value
        }

        [TestMethod]
        public void EncryptedMessage_FromJson_ValidJson_ShouldDeserializeCorrectly()
        {
            // Arrange
            var guid = Guid.NewGuid();
            string json = $@"{{
                ""ciphertext"": ""{Convert.ToBase64String(new byte[] { 1, 2, 3, 4 })}"",
                ""nonce"": ""{Convert.ToBase64String(new byte[] { 5, 6, 7, 8 })}"",
                ""messageNumber"": 42,
                ""senderDHKey"": ""{Convert.ToBase64String(new byte[] { 9, 10, 11, 12 })}"",
                ""timestamp"": 1634567890123,
                ""messageId"": ""{guid}""
            }}";

            // Act
            var message = EncryptedMessage.FromJson(json);

            // Assert
            Assert.IsNotNull(message);
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4 }, message.Ciphertext);
            CollectionAssert.AreEqual(new byte[] { 5, 6, 7, 8 }, message.Nonce);
            Assert.AreEqual(42, message.MessageNumber);
            CollectionAssert.AreEqual(new byte[] { 9, 10, 11, 12 }, message.SenderDHKey);
            Assert.AreEqual(1634567890123L, message.Timestamp);
            Assert.AreEqual(guid, message.MessageId);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EncryptedMessage_FromJson_EmptyJson_ShouldThrowException()
        {
            // Act & Assert - should throw ArgumentException
            EncryptedMessage.FromJson("");
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void EncryptedMessage_FromJson_InvalidJson_ShouldThrowException()
        {
            // Arrange - Invalid JSON format
            string invalidJson = "{this is not valid json}";

            // Act & Assert - should throw FormatException
            EncryptedMessage.FromJson(invalidJson);
        }

        [TestMethod]
        public void EncryptedMessage_ToDictionary_ShouldConvertCorrectly()
        {
            // Arrange
            var guid = Guid.NewGuid();
            var message = new EncryptedMessage
            {
                Ciphertext = new byte[] { 1, 2, 3, 4 },
                Nonce = new byte[] { 5, 6, 7, 8 },
                MessageNumber = 42,
                SenderDHKey = new byte[] { 9, 10, 11, 12 },
                Timestamp = 1634567890123L,
                MessageId = guid,
                SessionId = "test-session-123"
            };

            // Act
            var dict = message.ToDictionary();

            // Assert
            Assert.IsNotNull(dict);
            Assert.AreEqual(Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }), dict["ciphertext"]);
            Assert.AreEqual(Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }), dict["nonce"]);
            Assert.AreEqual(42, dict["messageNumber"]);
            Assert.AreEqual(Convert.ToBase64String(new byte[] { 9, 10, 11, 12 }), dict["senderDHKey"]);
            Assert.AreEqual(1634567890123L, dict["timestamp"]);
            Assert.AreEqual(guid.ToString(), dict["messageId"]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptedMessage_ToDictionary_NullCiphertext_ShouldThrowException()
        {
            // Arrange
            var message = new EncryptedMessage
            {
                Ciphertext = null,
                Nonce = new byte[] { 5, 6, 7, 8 },
                MessageNumber = 42,
                SenderDHKey = new byte[] { 9, 10, 11, 12 }
            };

            // Act & Assert - should throw ArgumentNullException
            message.ToDictionary();
        }

        [TestMethod]
        public void EncryptedMessage_Validate_ValidMessage_ShouldReturnTrue()
        {
            // Arrange
            var message = new EncryptedMessage
            {
                Ciphertext = new byte[] { 1, 2, 3, 4 },
                Nonce = new byte[] { 5, 6, 7, 8 },
                MessageNumber = 42,
                SenderDHKey = new byte[] { 9, 10, 11, 12 },
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            // Act
            bool isValid = message.Validate();

            // Assert
            Assert.IsTrue(isValid, "Valid message should pass validation");
        }

        [TestMethod]
        public void EncryptedMessage_Validate_NullCiphertext_ShouldReturnFalse()
        {
            // Arrange
            var message = new EncryptedMessage
            {
                Ciphertext = null,
                Nonce = new byte[] { 5, 6, 7, 8 },
                MessageNumber = 42,
                SenderDHKey = new byte[] { 9, 10, 11, 12 }
            };

            // Act
            bool isValid = message.Validate();

            // Assert
            Assert.IsFalse(isValid, "Message with null ciphertext should fail validation");
        }

        [TestMethod]
        public void EncryptedMessage_Validate_FutureTimestamp_ShouldReturnFalse()
        {
            // Arrange
            var message = new EncryptedMessage
            {
                Ciphertext = new byte[] { 1, 2, 3, 4 },
                Nonce = new byte[] { 5, 6, 7, 8 },
                MessageNumber = 42,
                SenderDHKey = new byte[] { 9, 10, 11, 12 },
                // Set timestamp to 10 minutes in the future
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (10 * 60 * 1000)
            };

            // Act
            bool isValid = message.Validate();

            // Assert
            Assert.IsFalse(isValid, "Message with future timestamp should fail validation");
        }

        [TestMethod]
        public void EncryptedMessage_WithNewEncryption_ShouldCreateNewInstance()
        {
            // Arrange
            var originalMessage = new EncryptedMessage
            {
                Ciphertext = new byte[] { 1, 2, 3, 4 },
                Nonce = new byte[] { 5, 6, 7, 8 },
                MessageNumber = 42,
                SenderDHKey = new byte[] { 9, 10, 11, 12 },
                Timestamp = 1634567890123L,
                MessageId = Guid.NewGuid()
            };

            byte[] newCiphertext = new byte[] { 13, 14, 15, 16 };
            byte[] newNonce = new byte[] { 17, 18, 19, 20 };

            // Act
            var newMessage = originalMessage.WithNewEncryption(newCiphertext, newNonce);

            // Assert
            Assert.IsNotNull(newMessage);
            Assert.AreNotSame(originalMessage, newMessage, "Should create a new instance");
            CollectionAssert.AreEqual(newCiphertext, newMessage.Ciphertext);
            CollectionAssert.AreEqual(newNonce, newMessage.Nonce);
            Assert.AreEqual(originalMessage.MessageNumber, newMessage.MessageNumber);
            CollectionAssert.AreEqual(originalMessage.SenderDHKey, newMessage.SenderDHKey);
            Assert.AreEqual(originalMessage.MessageId, newMessage.MessageId);
            Assert.IsTrue(newMessage.Timestamp >= originalMessage.Timestamp, "New timestamp should be later");
        }
    }
}