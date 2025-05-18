using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using LibEmiddle.Domain;

namespace LibEmiddle.Tests.Unit
{
    [TestClass]
    public class GroupMessageDeserializationTests
    {
        [TestMethod]
        public void EncryptedGroupMessage_FromDictionary_ValidInput_ShouldDeserializeCorrectly()
        {
            // Arrange
            var guid = Guid.NewGuid().ToString();
            var messageDict = new Dictionary<string, object>
            {
                ["MessageId"] = guid,
                ["GroupId"] = "test-group-123",
                ["SenderIdentityKey"] = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }),
                ["Ciphertext"] = Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }),
                ["Nonce"] = Convert.ToBase64String(new byte[] { 9, 10, 11, 12 }),
                ["Timestamp"] = 1634567890123L,
                ["RotationEpoch"] = 1634567800000L,
                ["Signature"] = Convert.ToBase64String(new byte[] { 13, 14, 15, 16 })
            };

            // Act
            var message = EncryptedGroupMessage.FromDictionary(messageDict);

            // Assert
            Assert.IsNotNull(message);
            Assert.AreEqual(guid, message.MessageId);
            Assert.AreEqual("test-group-123", message.GroupId);
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4 }, message.SenderIdentityKey);
            CollectionAssert.AreEqual(new byte[] { 5, 6, 7, 8 }, message.Ciphertext);
            CollectionAssert.AreEqual(new byte[] { 9, 10, 11, 12 }, message.Nonce);
            Assert.AreEqual(1634567890123L, message.Timestamp);
            Assert.AreEqual(1634567800000L, message.RotationEpoch);
            CollectionAssert.AreEqual(new byte[] { 13, 14, 15, 16 }, message.Signature);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptedGroupMessage_FromDictionary_NullDictionary_ShouldThrowException()
        {
            // Act & Assert - should throw ArgumentNullException
            EncryptedGroupMessage.FromDictionary(null);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void EncryptedGroupMessage_FromDictionary_MissingRequiredField_ShouldThrowException()
        {
            // Arrange - Missing required GroupId
            var messageDict = new Dictionary<string, object>
            {
                ["SenderIdentityKey"] = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }),
                ["Ciphertext"] = Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }),
                ["Nonce"] = Convert.ToBase64String(new byte[] { 9, 10, 11, 12 }),
                ["Timestamp"] = 1634567890123L
                // GroupId is missing
            };

            // Act & Assert - should throw FormatException
            EncryptedGroupMessage.FromDictionary(messageDict);
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void EncryptedGroupMessage_FromDictionary_InvalidBase64_ShouldThrowException()
        {
            // Arrange - Invalid Base64 string
            var messageDict = new Dictionary<string, object>
            {
                ["GroupId"] = "test-group-123",
                ["SenderIdentityKey"] = "Not a valid Base64 string!!!",
                ["Ciphertext"] = Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }),
                ["Nonce"] = Convert.ToBase64String(new byte[] { 9, 10, 11, 12 }),
                ["Timestamp"] = 1634567890123L
            };

            // Act & Assert - should throw FormatException
            EncryptedGroupMessage.FromDictionary(messageDict);
        }

        [TestMethod]
        public void EncryptedGroupMessage_FromDictionary_OptionalFields_ShouldSetDefaults()
        {
            // Arrange - Only required fields
            var messageDict = new Dictionary<string, object>
            {
                ["GroupId"] = "test-group-123",
                ["SenderIdentityKey"] = Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }),
                ["Ciphertext"] = Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }),
                ["Nonce"] = Convert.ToBase64String(new byte[] { 9, 10, 11, 12 }),
                ["Timestamp"] = 1634567890123L
                // MessageId, RotationEpoch, and Signature are missing
            };

            // Act
            var message = EncryptedGroupMessage.FromDictionary(messageDict);

            // Assert
            Assert.IsNotNull(message);
            Assert.IsNotNull(message.MessageId); // Should have a valid message ID
            Assert.AreEqual(0, message.RotationEpoch); // Should have default RotationEpoch
            Assert.IsNull(message.Signature); // Should have null Signature
        }

        [TestMethod]
        public void EncryptedGroupMessage_FromJson_ValidJson_ShouldDeserializeCorrectly()
        {
            // Arrange
            var guid = Guid.NewGuid().ToString();
            string json = $@"{{
                ""MessageId"": ""{guid}"",
                ""GroupId"": ""test-group-123"",
                ""SenderIdentityKey"": ""{Convert.ToBase64String(new byte[] { 1, 2, 3, 4 })}"",
                ""Ciphertext"": ""{Convert.ToBase64String(new byte[] { 5, 6, 7, 8 })}"",
                ""Nonce"": ""{Convert.ToBase64String(new byte[] { 9, 10, 11, 12 })}"",
                ""Timestamp"": 1634567890123,
                ""RotationEpoch"": 1634567800000,
                ""Signature"": ""{Convert.ToBase64String(new byte[] { 13, 14, 15, 16 })}"",
                ""Headers"": {{
                    ""Key1"": ""Value1"",
                    ""Key2"": ""Value2""
                }}
            }}";

            // Act
            var message = EncryptedGroupMessage.FromJson(json);

            // Assert
            Assert.IsNotNull(message);
            Assert.AreEqual(guid, message.MessageId);
            Assert.AreEqual("test-group-123", message.GroupId);
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3, 4 }, message.SenderIdentityKey);
            CollectionAssert.AreEqual(new byte[] { 5, 6, 7, 8 }, message.Ciphertext);
            CollectionAssert.AreEqual(new byte[] { 9, 10, 11, 12 }, message.Nonce);
            Assert.AreEqual(1634567890123L, message.Timestamp);
            Assert.AreEqual(1634567800000L, message.RotationEpoch);
            CollectionAssert.AreEqual(new byte[] { 13, 14, 15, 16 }, message.Signature);
            Assert.IsNotNull(message.Headers);
            Assert.AreEqual(2, message.Headers.Count);
            Assert.AreEqual("Value1", message.Headers["Key1"]);
            Assert.AreEqual("Value2", message.Headers["Key2"]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void EncryptedGroupMessage_FromJson_EmptyJson_ShouldThrowException()
        {
            // Act & Assert - should throw ArgumentException
            EncryptedGroupMessage.FromJson("");
        }

        [TestMethod]
        [ExpectedException(typeof(FormatException))]
        public void EncryptedGroupMessage_FromJson_InvalidJson_ShouldThrowException()
        {
            // Arrange - Invalid JSON format
            string invalidJson = "{this is not valid json}";

            // Act & Assert - should throw FormatException
            EncryptedGroupMessage.FromJson(invalidJson);
        }

        [TestMethod]
        public void EncryptedGroupMessage_ToDictionary_ShouldConvertCorrectly()
        {
            // Arrange
            var guid = Guid.NewGuid().ToString();
            var message = new EncryptedGroupMessage
            {
                MessageId = guid,
                GroupId = "test-group-123",
                SenderIdentityKey = new byte[] { 1, 2, 3, 4 },
                Ciphertext = new byte[] { 5, 6, 7, 8 },
                Nonce = new byte[] { 9, 10, 11, 12 },
                Timestamp = 1634567890123L,
                RotationEpoch = 1634567800000L,
                Signature = new byte[] { 13, 14, 15, 16 },
                Headers = new Dictionary<string, string>
                {
                    ["Key1"] = "Value1",
                    ["Key2"] = "Value2"
                }
            };

            // Act
            var dict = message.ToDictionary();

            // Assert
            Assert.IsNotNull(dict);
            Assert.AreEqual(guid, dict["MessageId"]);
            Assert.AreEqual("test-group-123", dict["GroupId"]);
            Assert.AreEqual(Convert.ToBase64String(new byte[] { 1, 2, 3, 4 }), dict["SenderIdentityKey"]);
            Assert.AreEqual(Convert.ToBase64String(new byte[] { 5, 6, 7, 8 }), dict["Ciphertext"]);
            Assert.AreEqual(Convert.ToBase64String(new byte[] { 9, 10, 11, 12 }), dict["Nonce"]);
            Assert.AreEqual(1634567890123L, dict["Timestamp"]);
            Assert.AreEqual(1634567800000L, dict["RotationEpoch"]);
            Assert.AreEqual(Convert.ToBase64String(new byte[] { 13, 14, 15, 16 }), dict["Signature"]);
            Assert.IsNotNull(dict["Headers"]);
            var headers = (Dictionary<string, string>)dict["Headers"];
            Assert.AreEqual(2, headers.Count);
            Assert.AreEqual("Value1", headers["Key1"]);
            Assert.AreEqual("Value2", headers["Key2"]);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void EncryptedGroupMessage_ToDictionary_NullGroupId_ShouldThrowException()
        {
            // Arrange
            var message = new EncryptedGroupMessage
            {
                GroupId = null!,
                SenderIdentityKey = new byte[] { 1, 2, 3, 4 },
                Ciphertext = new byte[] { 5, 6, 7, 8 },
                Nonce = new byte[] { 9, 10, 11, 12 },
                Timestamp = 1634567890123L
            };

            // Act & Assert - should throw ArgumentNullException
            message.ToDictionary();
        }

        [TestMethod]
        public void EncryptedGroupMessage_ToJson_ShouldSerializeCorrectly()
        {
            // Arrange
            var guid = Guid.NewGuid().ToString();
            var message = new EncryptedGroupMessage
            {
                MessageId = guid,
                GroupId = "test-group-123",
                SenderIdentityKey = new byte[] { 1, 2, 3, 4 },
                Ciphertext = new byte[] { 5, 6, 7, 8 },
                Nonce = new byte[] { 9, 10, 11, 12 },
                Timestamp = 1634567890123L,
                RotationEpoch = 1634567800000L,
                Signature = new byte[] { 13, 14, 15, 16 },
                Headers = new Dictionary<string, string>
                {
                    ["Key1"] = "Value1",
                    ["Key2"] = "Value2"
                }
            };

            // Act
            string json = message.ToJson();
            var deserializedMessage = EncryptedGroupMessage.FromJson(json);

            // Assert
            Assert.IsNotNull(deserializedMessage);
            Assert.AreEqual(message.MessageId, deserializedMessage.MessageId);
            Assert.AreEqual(message.GroupId, deserializedMessage.GroupId);
            CollectionAssert.AreEqual(message.SenderIdentityKey, deserializedMessage.SenderIdentityKey);
            CollectionAssert.AreEqual(message.Ciphertext, deserializedMessage.Ciphertext);
            CollectionAssert.AreEqual(message.Nonce, deserializedMessage.Nonce);
            Assert.AreEqual(message.Timestamp, deserializedMessage.Timestamp);
            Assert.AreEqual(message.RotationEpoch, deserializedMessage.RotationEpoch);
            CollectionAssert.AreEqual(message.Signature, deserializedMessage.Signature);
            Assert.IsNotNull(deserializedMessage.Headers);
            Assert.AreEqual(2, deserializedMessage.Headers.Count);
            Assert.AreEqual("Value1", deserializedMessage.Headers["Key1"]);
            Assert.AreEqual("Value2", deserializedMessage.Headers["Key2"]);
        }
    }
}