using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using FluentAssertions;
using Microsoft.Azure.Batch.SoftwareEntitlement.Common;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Tests
{
    public class EntitlementVerifierTests
    {
        // An entitlements object representing a complete set of claims
        private readonly NodeEntitlements _completeEntitlement;

        // An entitlement verification request which is valid for the above entitlement
        private readonly EntitlementVerificationRequest _validEntitlementRequest;

        // Generator used to create a token
        private readonly TokenGenerator _generator;

        // Verifier used to check the token
        private readonly EntitlementVerifier _verifier;

        // Current time - captured as a member so it doesn't change during a test
        private readonly DateTimeOffset _now = DateTimeOffset.Now;

        // A application identifiers for testing
        private readonly string _approvedApp = "contosofinance";

        // IP addresses to use
        private readonly IPAddress _approvedAddress = IPAddress.Parse("203.0.113.45");

        // CPU core counts
        private readonly int _cpuCoreCountMax = 2;

        // Claims relating to the Batch context in which the host is expected to be running
        private readonly string _batchAccountId = "testbatchaccount";
        private readonly string _poolId = "testpoolid";
        private readonly string _jobId = "testjobid";
        private readonly string _taskId = "testtaskid";

        // Host IDs
        private readonly string _sampleHostId = "should-not-change-for-a-single-entitlement";

        // Name for the approved entitlement
        private readonly string _entitlementIdentifer = "mystery-identifier";

        // Audience to which tokens should be addressed
        private readonly string _audience = "https://audience.region.batch.azure.test";

        // Issuer by which tokens should be created
        private readonly string _issuer = "https://issuer.region.batch.azure.test";

        // Logger that does nothing
        private readonly ILogger _nullLogger = NullLogger.Instance;

        // Key to use for signing
        private readonly SymmetricSecurityKey _signingKey;

        // Key to use for encryption
        private readonly SymmetricSecurityKey _encryptingKey;

        // Credentials used for encryption
        private readonly EncryptingCredentials _encryptingCredentials;

        // Credentials used for signing
        private readonly SigningCredentials _signingCredentials;

        public EntitlementVerifierTests()
        {
            // Hard coded key for unit testing only; actual operation will use a cert
            const string plainTextSigningKey = "This is my shared, not so secret, secret that needs to be very long!";
            _signingKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(plainTextSigningKey));

            _signingCredentials = new SigningCredentials(
                _signingKey, SecurityAlgorithms.HmacSha256Signature);

            // Hard coded key for unit testing only; actual operation will use a cert
            const string plainTextEncryptionKey = "This is another, not so secret, secret that needs to be very long!";
            _encryptingKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(plainTextEncryptionKey));

            _encryptingCredentials = new EncryptingCredentials(
                _encryptingKey, "dir", SecurityAlgorithms.Aes256CbcHmacSha512);

            _completeEntitlement = CreateEntitlements();
            _validEntitlementRequest = CreateRequest(_approvedApp, _approvedAddress, _sampleHostId, _cpuCoreCountMax);

            _verifier = CreateEntitlementVerifier(_signingKey, _encryptingKey);
            _generator = new TokenGenerator(_nullLogger, _signingCredentials, _encryptingCredentials);
        }

        private EntitlementVerifier CreateEntitlementVerifier(
            SecurityKey signingKey,
            SecurityKey encryptingKey,
            IHostVerifier hostVerifier = null)
        {
            var entitlementReader = new NodeEntitlementReader(_audience, _issuer, signingKey, encryptingKey);
            hostVerifier = hostVerifier ?? new StoredEntitlementHostVerifier();
            return new EntitlementVerifier(entitlementReader, hostVerifier);
        }

        private NodeEntitlements CreateEntitlements(EntitlementCreationOptions creationOptions = EntitlementCreationOptions.None)
        {
            var result = new NodeEntitlements()
                .FromInstant(_now)
                .UntilInstant(_now + TimeSpan.FromDays(7))
                .WithAudience(_audience)
                .WithIssuer(_issuer)
                .WithIpAddresses(_approvedAddress)
                .WithApplications(_approvedApp);

            if (!creationOptions.HasFlag(EntitlementCreationOptions.OmitIdentifier))
            {
                result = result.WithIdentifier(_entitlementIdentifer);
            }

            if (!creationOptions.HasFlag(EntitlementCreationOptions.OmitMachineId))
            {
                result = result.WithVirtualMachineId("virtual-machine-identifier");
            }

            if (!creationOptions.HasFlag(EntitlementCreationOptions.OmitCpuCoreCount))
            {
                result = result.WithCpuCoreCount(_cpuCoreCountMax);
            }

            if (!creationOptions.HasFlag(EntitlementCreationOptions.OmitBatchContext))
            {
                result = result
                    .WithBatchAccountId(_batchAccountId)
                    .WithPoolId(_poolId)
                    .WithJobId(_jobId)
                    .WithTaskId(_taskId);
            }

            return result;
        }

        /// <summary>
        /// Options used to control the creation of an <see cref="NodeEntitlements"/> instance
        /// for testing.
        /// </summary>
        [Flags]
        private enum EntitlementCreationOptions
        {
            None = 0,
            OmitIdentifier = 1,
            OmitMachineId = 2,
            OmitCpuCoreCount = 4,
            OmitBatchContext = 8
        }

        private EntitlementVerificationRequest CreateRequest(
            string application,
            IPAddress ipAddress,
            string hostId,
            int? cpuCoreCount)
        {
            return new EntitlementVerificationRequest(application, ipAddress)
            {
                HostId = hostId,
                CpuCoreCount = cpuCoreCount
            };
        }

        public class ConfigurationCheck : EntitlementVerifierTests
        {
            // Base case check that our valid entitlement actually works to create a token
            // If this test fails, first check to see if our test data is still valid
            [Fact]
            public void GivenValidEntitlement_ReturnsSuccess()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
            }
        }

        public class TokenTimeSpan : EntitlementVerifierTests
        {
            private readonly TimeSpan _oneWeek = TimeSpan.FromDays(7);

            private readonly TimeSpan _oneDay = TimeSpan.FromDays(1);

            [Fact]
            public void GivenValidEntitlement_HasExpectedNotBefore()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.NotBefore.Should().BeCloseTo(_completeEntitlement.NotBefore, precision: 1000);
            }

            [Fact]
            public void GivenValidEntitlement_HasExpectedNotAfter()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.NotAfter.Should().BeCloseTo(_completeEntitlement.NotAfter, precision: 1000);
            }

            [Fact]
            public void WhenEntitlementHasExpired_ReturnsExpectedError()
            {
                var entitlement = _completeEntitlement
                    .FromInstant(_now - _oneWeek)
                    .UntilInstant(_now - _oneDay);
                var token = _generator.Generate(entitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().Contain(e => e.Contains("expired"));
            }

            [Fact]
            public void WhenEntitlementHasNotYetStarted_ReturnsExpectedError()
            {
                var entitlement = _completeEntitlement
                    .FromInstant(_now + _oneDay)
                    .UntilInstant(_now + _oneWeek);
                var token = _generator.Generate(entitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().Contain(e => e.Contains("will not be valid"));
            }
        }

        public class IssuedAt : EntitlementVerifierTests
        {
            private readonly DateTimeOffset _inPast = new DateTime(2016, 1, 1);

            [Fact]
            public void WhenIssueDateSpecified_IsReturnedByVerifier()
            {
                var token = _generator.Generate(_completeEntitlement.WithIssuedAt(_inPast));
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.IssuedAt.Should().Be(_inPast);
            }
        }

        public class VirtualMachineIdentifier : EntitlementVerifierTests
        {
            [Fact]
            public void WhenIdentifierIncluded_IsReturnedByVerifier()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.VirtualMachineId.Should().Be(_completeEntitlement.VirtualMachineId);
            }

            [Fact]
            public void WhenIdentifierOmitted_EntitlementHasNoVirtualMachineIdentifier()
            {
                var entitlements = CreateEntitlements(EntitlementCreationOptions.OmitMachineId);
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.VirtualMachineId.Should().BeNullOrEmpty();
            }
        }

        public class Applications : EntitlementVerifierTests
        {
            private readonly string _otherApp1 = "contosoit";
            private readonly string _otherApp2 = "contosohr";

            [Fact]
            public void WhenEntitlementContainsOnlyTheRequestedApplication_ReturnsExpectedApplication()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.Applications.Should().Contain(_approvedApp);
            }

            [Fact]
            public void WhenEntitlementContainsOnlyADifferentApplication_ReturnsError()
            {
                var token = _generator.Generate(_completeEntitlement);
                var request = CreateRequest(_otherApp1, _approvedAddress, _sampleHostId, _cpuCoreCountMax);
                var result = _verifier.Verify(request, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().Contain(e => e.Contains(_otherApp1));
            }

            [Fact]
            public void WhenEntitlementContainsMultipleApplicationsButNotTheRequestedApplication_ReturnsError()
            {
                var entitlement = _completeEntitlement.WithApplications(_otherApp1, _otherApp2);
                var token = _generator.Generate(entitlement);

                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().NotBeEmpty();
            }

            [Fact]
            public void WhenEntitlementContainsMultipleApplicationsIncludingTheRequestedApplication_ReturnsExpectedApplication()
            {
                var entitlement = _completeEntitlement.WithApplications(_approvedApp, _otherApp1, _otherApp2);
                var token = _generator.Generate(entitlement);

                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.Applications.Should().Contain(_approvedApp);
            }

            [Fact]
            public void WhenEntitlementContainsNoApplications_ReturnsError()
            {
                var entitlements = _completeEntitlement.WithApplications();
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().Contain(e => e.Contains(_approvedApp));
            }
        }

        public class IpAddressProperty : EntitlementVerifierTests
        {
            private readonly IPAddress _otherAddress = IPAddress.Parse("203.0.113.42");

            [Fact]
            public void WhenEntitlementContainsIp_ReturnsIpAddress()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.IpAddresses.Should().Contain(_approvedAddress);
            }

            [Fact]
            public void WhenEntitlementContainsOtherIp_ReturnsError()
            {
                var entitlements = _completeEntitlement.WithIpAddresses(_otherAddress);
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().NotBeEmpty();
            }

            [Fact]
            public void WhenEntitlementHasNoIp_ReturnsError()
            {
                var entitlements = _completeEntitlement.WithIpAddresses();
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().Contain(e => e.Contains(_approvedAddress.ToString()));
            }
        }

        public class HostIdProperty : EntitlementVerifierTests
        {
            private class NegativeHostVerifier : IHostVerifier
            {
                public bool Verify(NodeEntitlements entitlement, string hostId) => false;
            }

            [Fact]
            public void WhenHostVerifierReturnsFalse_ReturnsError()
            {
                var verifier = CreateEntitlementVerifier(_signingKey, _encryptingKey, new NegativeHostVerifier());
                var token = _generator.Generate(_completeEntitlement);
                var result = verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().Contain($"Host {_sampleHostId} is not allowed for entitlement {_entitlementIdentifer}");
            }
        }

        public class CpuCoreCountProperty : EntitlementVerifierTests
        {
            private readonly int _lowCpuCoreCount;
            private readonly int _tooHighCpuCoreCount;

            public CpuCoreCountProperty()
            {
                _lowCpuCoreCount = _cpuCoreCountMax - 1;
                _tooHighCpuCoreCount = _cpuCoreCountMax + 1;
            }

            [Fact]
            public void WhenCoreCountIsLessThanEntitlement_ReturnsMaxCoreCount()
            {
                var request = CreateRequest(_approvedApp, _approvedAddress, _sampleHostId, _lowCpuCoreCount);
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(request, token);
                result.HasValue.Should().BeTrue();
                result.Value.CpuCoreCount.Should().Be(_completeEntitlement.CpuCoreCount);
            }

            [Fact]
            public void WhenCoreCountEqualsEntitlement_ReturnsMaxCoreCount()
            {
                var request = CreateRequest(_approvedApp, _approvedAddress, _sampleHostId, _completeEntitlement.CpuCoreCount);
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(request, token);
                result.HasValue.Should().BeTrue();
                result.Value.CpuCoreCount.Should().Be(_completeEntitlement.CpuCoreCount);
            }

            [Fact]
            public void WhenCoreCountExceedsEntitlement_ReturnsError()
            {
                var request = CreateRequest(_approvedApp, _approvedAddress, _sampleHostId, _tooHighCpuCoreCount);
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(request, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().NotBeEmpty();
            }

            [Fact]
            public void WhenEntitlementHasNoCoreCount_ReturnsError()
            {
                var entitlements = CreateEntitlements(EntitlementCreationOptions.OmitCpuCoreCount);
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().NotBeEmpty();
            }
        }

        public class IdentifierProperty : EntitlementVerifierTests
        {
            [Fact]
            public void WhenValidEntitlementSpecifiesIdentifier_ReturnsIdentifier()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.Identifier.Should().Be(_entitlementIdentifer);
            }

            [Fact]
            public void WhenIdentifierOmitted_ReturnsError()
            {
                var entitlements = CreateEntitlements(EntitlementCreationOptions.OmitIdentifier);
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().Contain(e => e.Contains("identifier"));
            }
        }

        public class AudienceProperty : EntitlementVerifierTests
        {
            [Fact]
            public void WhenAudienceOfTokenDiffers_ReturnsError()
            {
                var entitlements = CreateEntitlements()
                    .WithAudience("http://not.the.audience.you.expected");
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeFalse();
                result.Errors.Should().Contain(e => e.Contains("audience"));
            }
        }

        public class BatchAccountIdProperty : EntitlementVerifierTests
        {
            [Fact]
            public void WhenBatchAccountIdSpecified_ReturnsBatchAccountId()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.Value.BatchAccountId.Should().Be(_batchAccountId);
            }

            [Fact]
            public void WhenBatchAccountIdOmitted_ReturnsNull()
            {
                var entitlements = CreateEntitlements(EntitlementCreationOptions.OmitBatchContext)
                    .WithPoolId(_poolId)
                    .WithJobId(_jobId)
                    .WithTaskId(_taskId);
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.BatchAccountId.Should().BeNull();
            }
        }

        public class PoolIdProperty : EntitlementVerifierTests
        {
            [Fact]
            public void WhenPoolIdSpecified_ReturnsPoolId()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.Value.PoolId.Should().Be(_poolId);
            }

            [Fact]
            public void WhenPoolIdOmitted_ReturnsNull()
            {
                var entitlements = CreateEntitlements(EntitlementCreationOptions.OmitBatchContext)
                    .WithBatchAccountId(_batchAccountId)
                    .WithJobId(_jobId)
                    .WithTaskId(_taskId);
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.PoolId.Should().BeNull();
            }
        }

        public class JobIdProperty : EntitlementVerifierTests
        {
            [Fact]
            public void WhenJobIdSpecified_ReturnsJobId()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.Value.JobId.Should().Be(_jobId);
            }

            [Fact]
            public void WhenJobIdOmitted_ReturnsNull()
            {
                var entitlements = CreateEntitlements(EntitlementCreationOptions.OmitBatchContext)
                    .WithBatchAccountId(_batchAccountId)
                    .WithPoolId(_poolId)
                    .WithTaskId(_taskId);
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.JobId.Should().BeNull();
            }
        }

        public class TaskIdProperty : EntitlementVerifierTests
        {
            [Fact]
            public void WhenTaskIdSpecified_ReturnsTaskId()
            {
                var token = _generator.Generate(_completeEntitlement);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.Value.TaskId.Should().Be(_taskId);
            }

            [Fact]
            public void WhenTaskIdOmitted_ReturnsNull()
            {
                var entitlements = CreateEntitlements(EntitlementCreationOptions.OmitBatchContext)
                    .WithBatchAccountId(_batchAccountId)
                    .WithPoolId(_poolId)
                    .WithJobId(_jobId);
                var token = _generator.Generate(entitlements);
                var result = _verifier.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.TaskId.Should().BeNull();
            }
        }

        /// <summary>
        /// Tests to check that enforcement works end to end with no signing key 
        /// </summary>
        public class WithoutSigning : EntitlementVerifierTests
        {
            // Generator with no signing key used to create a token
            private readonly TokenGenerator _generatorWithNoSigningKey;

            // Verifier with no signing key used to check the token
            private readonly EntitlementVerifier _verifierWithNoSigningKey;

            public WithoutSigning()
            {
                _verifierWithNoSigningKey = CreateEntitlementVerifier(signingKey: null, _encryptingKey);
                _generatorWithNoSigningKey = new TokenGenerator(_nullLogger, null, _encryptingCredentials);
            }

            [Fact]
            public void WhenEntitlementContainsOnlyTheRequestedApplication_ReturnsExpectedApplication()
            {
                var token = _generatorWithNoSigningKey.Generate(_completeEntitlement);
                var result = _verifierWithNoSigningKey.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.Applications.Should().Contain(_approvedApp);
            }
        }

        /// <summary>
        /// Tests to check that enforcement works end to end with no encryption key 
        /// </summary>
        public class WithoutEncryption : EntitlementVerifierTests
        {
            // Generator with no signing key used to create a token
            private readonly TokenGenerator _generatorWithNoEncryptionKey;

            // Verifier with no signing key used to check the token
            private readonly EntitlementVerifier _verifierWithNoEncryptionKey;

            public WithoutEncryption()
            {
                _verifierWithNoEncryptionKey = CreateEntitlementVerifier(_signingKey, encryptingKey: null);
                _generatorWithNoEncryptionKey = new TokenGenerator(_nullLogger, _signingCredentials, encryptingCredentials: null);
            }

            [Fact]
            public void WhenEntitlementContainsOnlyTheRequestedApplication_ReturnsExpectedApplication()
            {
                var token = _generatorWithNoEncryptionKey.Generate(_completeEntitlement);
                var result = _verifierWithNoEncryptionKey.Verify(_validEntitlementRequest, token);
                result.HasValue.Should().BeTrue();
                result.Value.Applications.Should().Contain(_approvedApp);
            }
        }

        public class WithCertificates : EntitlementVerifierTests
        {
            [Theory(Skip = "Specify a certificate thumbprint in TestCaseKeys() to enable this test.")]
            [MemberData(nameof(TestCaseKeys))]
            public void WhenSignedByCertificate_ReturnsExpectedResult(SecurityKey key)
            {
                // Arrange
                var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha512Signature);
                var verifier = CreateEntitlementVerifier(key, encryptingKey: null);
                var generator = new TokenGenerator(_nullLogger, signingCredentials, encryptingCredentials: null);
                // Act
                var token = generator.Generate(_completeEntitlement);
                var result = verifier.Verify(_validEntitlementRequest, token);
                // Assert
                result.Errors.Should().BeEmpty();
                result.Value.Applications.Should().Contain(_approvedApp);
            }

            [Theory(Skip = "Specify a certificate thumbprint in TestCaseKeys() to enable this test.")]
            [MemberData(nameof(TestCaseKeys))]
            public void WhenEncryptedByCertificate_ReturnsExpectedResult(SecurityKey key)
            {
                // Arrange
                var encryptingCredentials = new EncryptingCredentials(key, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512);
                var verifier = CreateEntitlementVerifier(signingKey: null, encryptingKey: key);
                var generator = new TokenGenerator(_nullLogger, signingCredentials: null, encryptingCredentials: encryptingCredentials);
                // Act
                var token = generator.Generate(_completeEntitlement);
                var result = verifier.Verify(_validEntitlementRequest, token);
                // Assert
                result.Errors.Should().BeEmpty();
                result.Value.Applications.Should().Contain(_approvedApp);
            }

            public static IEnumerable<object[]> TestCaseKeys()
            {
                // To use this test, change the next line by entering a thumbprint that exists on the test machine
                var thumbprint = new CertificateThumbprint("<thumbprint-goes-here>");
                var store = new CertificateStore();
                var cert = store.FindByThumbprint("test", thumbprint);
                if (!cert.HasValue)
                {
                    throw new InvalidOperationException(cert.Errors.First());
                }

                var parameters = cert.Value.GetRSAPrivateKey().ExportParameters(includePrivateParameters: true);
                var key = new RsaSecurityKey(parameters);

                yield return new object[] { key };
            }
        }
    }
}
