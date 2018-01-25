using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Microsoft.Azure.Batch.SoftwareEntitlement.Common;
using Xunit;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Tests
{
    /// <summary>
    /// Tests to ensure the <see cref="ServerOptionBuilder"/> correctly reports error 
    /// cases for each possible parameter
    /// </summary>
    public class ServerOptionBuilderTests
    {
        private static readonly CertificateThumbprint ConnectionCertificateThumbprint
            = new CertificateThumbprint("1S TR UL EO FC ER TC LU BI SD ON TT AL KA BO UT CE RT CL UB");

        // A valid set of command line arguments for testing
        private readonly ServerCommandLine _commandLine = new ServerCommandLine
        {
            ConnectionCertificateThumbprint = ConnectionCertificateThumbprint.ToString()
        };

        private const string CertificateNotFoundError = "Certificate not found test error";

        private readonly ICertificateStore _certificateStoreWithConnectionCertificate = new FakeCertificateStore(
            CertificateNotFoundError,
            (ConnectionCertificateThumbprint, new X509Certificate2()));

        public class ServerUrl : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithEmptyServerUrl_SetsDefaultServerUrl()
            {
                _commandLine.ServerUrl = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.Value.ServerUrl.Should().Be(ServerCommandLine.DefaultServerUrl);
            }

            [Fact]
            public void Build_WithHttpServerUrl_HasErrorForServerUrl()
            {
                _commandLine.ServerUrl = "http://www.example.com";
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.Errors.Should().Contain(e => e.Contains("Server endpoint URL"));
            }

            [Fact]
            public void WithValidServerUrl_ConfigureServerUrl()
            {
                _commandLine.ServerUrl = "https://example.com/";
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.Value.ServerUrl.ToString().Should().Be(_commandLine.ServerUrl);
            }
        }

        public class ConnectionThumbprint : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithNoConnectionThumbprint_DoesNotReturnValue()
            {
                _commandLine.ConnectionCertificateThumbprint = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.HasValue.Should().BeFalse();
            }

            [Fact]
            public void Build_WithNoConnectionThumbprint_HasErrorForConnection()
            {
                _commandLine.ConnectionCertificateThumbprint = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.Errors.Should().Contain(e => e.Contains("connection"));
            }

            [Fact]
            public void Build_WithUnknownConnectionThumbprint_HasErrorForConnection()
            {
                _commandLine.ConnectionCertificateThumbprint = "2N DR UL EO FC ER TC LU BI SD ON TT AL KA BO UT CE RT CL UB";
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.Errors.Should().Contain(CertificateNotFoundError);
            }
        }

        public class Audience : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithEmptyAudience_HasDefaultValueForAudience()
            {
                _commandLine.Audience = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.Value.Audience.Should().NotBeNullOrEmpty();
            }
        }

        public class Issuer : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithEmptyIssuer_HasDefaultValueForIssuer()
            {
                _commandLine.Issuer = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.Value.Issuer.Should().NotBeNullOrEmpty();
            }
        }

        public class ExitAfterRequest : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithoutExitAfterRequest_ShouldHaveDefault()
            {
                _commandLine.ExitAfterRequest = false;
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.Value.ExitAfterRequest.Should().BeFalse();
            }

            [Fact]
            public void Build_WithExitAfterRequest_ConfiguresValue()
            {
                _commandLine.ExitAfterRequest = true;
                var options = ServerOptionBuilder.Build(_commandLine, _certificateStoreWithConnectionCertificate);
                options.Value.ExitAfterRequest.Should().BeTrue();
            }
        }
    }
}
