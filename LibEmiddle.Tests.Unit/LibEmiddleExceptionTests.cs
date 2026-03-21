using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using LibEmiddle.Domain.Exceptions;

namespace LibEmiddle.Tests.Unit
{
    /// <summary>
    /// Unit tests for <see cref="LibEmiddleException"/> and <see cref="LibEmiddleErrorCode"/>.
    /// </summary>
    [TestClass]
    public class LibEmiddleExceptionTests
    {
        // ------------------------------------------------------------------ //
        //  Constructor and property tests                                      //
        // ------------------------------------------------------------------ //

        [TestMethod]
        public void Constructor_SetsMessage()
        {
            // Arrange / Act
            var ex = new LibEmiddleException("test message", LibEmiddleErrorCode.Unknown);

            // Assert
            Assert.AreEqual("test message", ex.Message);
        }

        [TestMethod]
        public void Constructor_SetsErrorCode()
        {
            // Arrange / Act
            var ex = new LibEmiddleException("msg", LibEmiddleErrorCode.DecryptionFailed);

            // Assert
            Assert.AreEqual(LibEmiddleErrorCode.DecryptionFailed, ex.ErrorCode);
        }

        [TestMethod]
        public void Constructor_DefaultInnerExceptionIsNull()
        {
            // Arrange / Act
            var ex = new LibEmiddleException("msg", LibEmiddleErrorCode.Unknown);

            // Assert
            Assert.IsNull(ex.InnerException);
        }

        [TestMethod]
        public void Constructor_SetsInnerException_WhenProvided()
        {
            // Arrange
            var inner = new InvalidOperationException("inner");

            // Act
            var ex = new LibEmiddleException("outer", LibEmiddleErrorCode.TransportError, inner);

            // Assert
            Assert.AreSame(inner, ex.InnerException);
        }

        [TestMethod]
        public void IsSubclassOfException()
        {
            // Verify the inheritance contract so callers that catch Exception still work.
            var ex = new LibEmiddleException("msg", LibEmiddleErrorCode.Unknown);

            Assert.IsInstanceOfType(ex, typeof(Exception));
        }

        // ------------------------------------------------------------------ //
        //  Error code round-trips for every enum value                        //
        // ------------------------------------------------------------------ //

        [TestMethod]
        public void ErrorCode_Unknown()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.Unknown);
            Assert.AreEqual(LibEmiddleErrorCode.Unknown, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_InvalidBundle()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.InvalidBundle);
            Assert.AreEqual(LibEmiddleErrorCode.InvalidBundle, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_ReplayDetected()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.ReplayDetected);
            Assert.AreEqual(LibEmiddleErrorCode.ReplayDetected, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_DecryptionFailed()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.DecryptionFailed);
            Assert.AreEqual(LibEmiddleErrorCode.DecryptionFailed, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_TransportError()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.TransportError);
            Assert.AreEqual(LibEmiddleErrorCode.TransportError, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_KeyNotFound()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.KeyNotFound);
            Assert.AreEqual(LibEmiddleErrorCode.KeyNotFound, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_SessionNotFound()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.SessionNotFound);
            Assert.AreEqual(LibEmiddleErrorCode.SessionNotFound, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_DeviceNotFound()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.DeviceNotFound);
            Assert.AreEqual(LibEmiddleErrorCode.DeviceNotFound, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_OPKExhausted()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.OPKExhausted);
            Assert.AreEqual(LibEmiddleErrorCode.OPKExhausted, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_InvalidKey()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.InvalidKey);
            Assert.AreEqual(LibEmiddleErrorCode.InvalidKey, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_InvalidMessage()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.InvalidMessage);
            Assert.AreEqual(LibEmiddleErrorCode.InvalidMessage, ex.ErrorCode);
        }

        [TestMethod]
        public void ErrorCode_PermissionDenied()
        {
            var ex = new LibEmiddleException("m", LibEmiddleErrorCode.PermissionDenied);
            Assert.AreEqual(LibEmiddleErrorCode.PermissionDenied, ex.ErrorCode);
        }

        // ------------------------------------------------------------------ //
        //  Throw and catch behaviour                                           //
        // ------------------------------------------------------------------ //

        [TestMethod]
        [ExpectedException(typeof(LibEmiddleException))]
        public void CanBeThrownAndCaughtAsLibEmiddleException()
        {
            throw new LibEmiddleException("thrown", LibEmiddleErrorCode.InvalidKey);
        }

        [TestMethod]
        public void CanBeCaughtAsBaseException()
        {
            // Verify LibEmiddleException is catchable as base Exception (inheritance)
            bool caught = false;
            try
            {
                throw new LibEmiddleException("thrown", LibEmiddleErrorCode.TransportError);
            }
            catch (Exception)
            {
                caught = true;
            }
            Assert.IsTrue(caught, "LibEmiddleException must be catchable as base Exception.");
        }

        [TestMethod]
        public void ErrorCodePreservedAfterCatch()
        {
            // Arrange
            LibEmiddleErrorCode capturedCode = LibEmiddleErrorCode.Unknown;

            // Act
            try
            {
                throw new LibEmiddleException("replay!", LibEmiddleErrorCode.ReplayDetected);
            }
            catch (LibEmiddleException ex)
            {
                capturedCode = ex.ErrorCode;
            }

            // Assert
            Assert.AreEqual(LibEmiddleErrorCode.ReplayDetected, capturedCode);
        }

        [TestMethod]
        public void InnerExceptionPreservedAfterCatch()
        {
            // Arrange
            var inner = new ArgumentException("bad arg");
            LibEmiddleException caught = null;

            // Act
            try
            {
                throw new LibEmiddleException("wrapper", LibEmiddleErrorCode.InvalidBundle, inner);
            }
            catch (LibEmiddleException ex)
            {
                caught = ex;
            }

            // Assert
            Assert.IsNotNull(caught);
            Assert.AreSame(inner, caught.InnerException);
            Assert.AreEqual(LibEmiddleErrorCode.InvalidBundle, caught.ErrorCode);
        }

        // ------------------------------------------------------------------ //
        //  TransportError codes – verify SecureWebSocketClient uses them      //
        // ------------------------------------------------------------------ //

        [TestMethod]
        public void TransportError_IsSubclassOfException_ForExistingCatchers()
        {
            // The SecureWebSocketClient tests catch Exception.
            // Verify LibEmiddleException satisfies that contract.
            Exception ex = new LibEmiddleException("transport", LibEmiddleErrorCode.TransportError);
            Assert.IsInstanceOfType(ex, typeof(Exception));
            Assert.AreEqual(LibEmiddleErrorCode.TransportError,
                ((LibEmiddleException)ex).ErrorCode);
        }
    }
}
