using FluentAssertions;
using Xunit;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Tests
{
    /// <summary>
    /// Tests to ensure the <see cref="ServerOptionBuilder"/> correctly reports error 
    /// cases for each possible parameter
    /// </summary>
    public class ServerOptionBuilderTests
    {
        // One thumbprint string to use for testing
        private readonly string _thumbprint = "1S TR UL EO FC ER TC LU BI SD ON TT AL KA BO UT CE RT CL UB";

        // Server options for testing
        private readonly ServerCommandLine _commandLine = new ServerCommandLine();

        // Building a ServerOptions object consists of two actions for each property:
        // 1. Validating/parsing/defaulting the user input; and
        // 2. Initializing a copy of the ServerOptions object with the appropriate
        //    property value set.
        // To ensure the second part is not missed, we're unit testing both of these
        // actions together. We want to test each property individually, but some
        // properties are intended to be mandatory, and their absence will cause
        // errors unrelated to the property being tested. To work around this we use
        // a "permissive" option which changes the behaviour of the builder such that
        // the enforcement of mandatory properties is bypassed.
        private readonly ServerOptionBuilderOptions _permissiveOptions =
            ServerOptionBuilderOptions.ConnectionThumbprintOptional;

        public class ServerUrl : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithEmptyServerUrl_SetsDefaultServerUrl()
            {
                _commandLine.ServerUrl = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine, _permissiveOptions);
                options.Value.ServerUrl.Should().Be(ServerCommandLine.DefaultServerUrl);
            }

            [Fact]
            public void Build_WithHttpServerUrl_HasErrorForServerUrl()
            {
                _commandLine.ServerUrl = "http://www.example.com";
                var options = ServerOptionBuilder.Build(_commandLine);
                options.Errors.Should().Contain(e => e.Contains("Server endpoint URL"));
            }

            [Fact]
            public void WithValidServerUrl_ConfigureServerUrl()
            {
                _commandLine.ServerUrl = "https://example.com/";
                var options = ServerOptionBuilder.Build(_commandLine, _permissiveOptions);
                options.Value.ServerUrl.ToString().Should().Be(_commandLine.ServerUrl);
            }
        }

        public class ConnectionThumbprint : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithNoConnectionThumbprint_DoesNotReturnValue()
            {
                _commandLine.ConnectionCertificateThumbprint = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine);
                options.HasValue.Should().BeFalse();
            }

            [Fact]
            public void Build_WithNoConnectionThumbprint_HasErrorForConnection()
            {
                _commandLine.ConnectionCertificateThumbprint = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine);
                options.Errors.Should().Contain(e => e.Contains("connection"));
            }

            [Fact]
            public void Build_WithUnknownConnectionThumbprint_HasErrorForConnection()
            {
                _commandLine.ConnectionCertificateThumbprint = _thumbprint;
                var options = ServerOptionBuilder.Build(_commandLine);
                options.Errors.Should().Contain(e => e.Contains("connection"));
            }
        }

        public class Audience : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithEmptyAudience_HasDefaultValueForAudience()
            {
                _commandLine.Audience = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine, _permissiveOptions);
                options.Value.Audience.Should().NotBeNullOrEmpty();
            }
        }

        public class Issuer : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithEmptyIssuer_HasDefaultValueForIssuer()
            {
                _commandLine.Issuer = string.Empty;
                var options = ServerOptionBuilder.Build(_commandLine, _permissiveOptions);
                options.Value.Issuer.Should().NotBeNullOrEmpty();
            }
        }

        public class ExitAfterRequest : ServerOptionBuilderTests
        {
            [Fact]
            public void Build_WithoutExitAfterRequest_ShouldHaveDefault()
            {
                _commandLine.ExitAfterRequest = false;
                var options = ServerOptionBuilder.Build(_commandLine, _permissiveOptions);
                options.Value.ExitAfterRequest.Should().BeFalse();
            }

            [Fact]
            public void Build_WithExitAfterRequest_ConfiguresValue()
            {
                _commandLine.ExitAfterRequest = true;
                var options = ServerOptionBuilder.Build(_commandLine, _permissiveOptions);
                options.Value.ExitAfterRequest.Should().BeTrue();
            }
        }
    }
}
