using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Azure.Batch.SoftwareEntitlement.Common;

namespace Microsoft.Azure.Batch.SoftwareEntitlement
{
    /// <summary>
    /// A factory object that tries to create a <see cref="ServerOptions"/> instance when given the 
    /// <see cref="ServerCommandLine"/> specified by the user.
    /// </summary>
    public class ServerOptionBuilder
    {
        // Reference to the server command line we wrap
        private readonly ServerCommandLine _commandLine;

        // Reference to a store in which we can search for certificates
        private readonly ICertificateStore _certificateStore;

        /// <summary>
        /// Initializes a new instance of the <see cref="ServerOptionBuilder"/> class
        /// </summary>
        /// <param name="commandLine">Options provided on the command line.</param>
        /// <param name="certificateStore">A store to check supplied certificates against.</param>
        public ServerOptionBuilder(
            ServerCommandLine commandLine,
            ICertificateStore certificateStore)
        {
            _commandLine = commandLine;
            _certificateStore = certificateStore;
        }

        /// <summary>
        /// Build an instance of <see cref="ServerOptions"/> from the information supplied on the 
        /// command line by the user
        /// </summary>
        /// <returns>Either a usable (and completely valid) <see cref="ServerOptions"/> or a set 
        /// of errors.</returns>
        public Result<ServerOptions, ErrorCollection> Build() =>
            Result.FromOk(new ServerOptions())
                .With(ServerUrl(), (options, serverUrl) => options.WithServerUrl(serverUrl))
                .With(ConnectionCertificate(), (options, connCert) => options.WithConnectionCertificate(connCert))
                .With(SigningCertificate(), (options, signCert) => options.WithSigningCertificate(signCert))
                .With(EncryptingCertificate(), (options, encryptCert) => options.WithEncryptionCertificate(encryptCert))
                .With(Audience(), (options, audience) => options.WithAudience(audience))
                .With(Issuer(), (options, issuer) => options.WithIssuer(issuer))
                .With(ExitAfterRequest(), (options, exit) => options.WithAutomaticExitAfterOneRequest(exit));

        /// <summary>
        /// Find the server URL for our hosting
        /// </summary>
        /// <returns>An <see cref="Result{Uri,ErrorCollection}"/> containing either the URL to use or any 
        /// relevant errors.</returns>
        private Result<Uri, ErrorCollection> ServerUrl()
        {
            // If the server URL is not specified, default it.
            var serverUrl = string.IsNullOrWhiteSpace(_commandLine.ServerUrl)
                ? ServerCommandLine.DefaultServerUrl
                : _commandLine.ServerUrl;

            try
            {
                var result = new Uri(serverUrl);
                if (!result.HasScheme("https"))
                {
                    return ErrorCollection.Create("Server endpoint URL must specify https://");
                }

                return result;
            }
            catch (Exception e)
            {
                return ErrorCollection.Create($"Invalid server endpoint URL specified ({e.Message})");
            }
        }

        /// <summary>
        /// Find the certificate to use for HTTPS connections
        /// </summary>
        /// <returns>Certificate, if found; error details otherwise.</returns>
        private Result<X509Certificate2, ErrorCollection> ConnectionCertificate()
        {
            if (string.IsNullOrEmpty(_commandLine.ConnectionCertificateThumbprint))
            {
                return ErrorCollection.Create("A connection thumbprint is required.");
            }

            return FindCertificate("connection", _commandLine.ConnectionCertificateThumbprint);
        }

        /// <summary>
        /// Find the certificate to use for signing tokens
        /// </summary>
        /// <returns>Certificate, if found; error details otherwise.</returns>
        private Result<X509Certificate2, ErrorCollection> SigningCertificate()
        {
            if (string.IsNullOrEmpty(_commandLine.SigningCertificateThumbprint))
            {
                // No certificate requested, no need to look for one
                return null as X509Certificate2;
            }

            return FindCertificate("signing", _commandLine.SigningCertificateThumbprint);
        }

        /// <summary>
        /// Find the certificate to use for encrypting tokens
        /// </summary>
        /// <returns>Certificate, if found; error details otherwise.</returns>
        private Result<X509Certificate2, ErrorCollection> EncryptingCertificate()
        {
            if (string.IsNullOrEmpty(_commandLine.EncryptionCertificateThumbprint))
            {
                // No certificate requested, no need to look for one
                return null as X509Certificate2;
            }

            return FindCertificate("encrypting", _commandLine.EncryptionCertificateThumbprint);
        }

        /// <summary>
        /// Return the audience required 
        /// </summary>
        /// <returns>Audience from the commandline, if provided; default value otherwise.</returns>
        private Result<string, ErrorCollection> Audience()
        {
            if (string.IsNullOrEmpty(_commandLine.Audience))
            {
                return Claims.DefaultAudience;
            }

            return _commandLine.Audience;
        }

        /// <summary>
        /// Return the issuer required 
        /// </summary>
        /// <returns>Issuer from the commandline, if provided; default value otherwise.</returns>
        private Result<string, ErrorCollection> Issuer()
        {
            if (string.IsNullOrEmpty(_commandLine.Issuer))
            {
                return Claims.DefaultIssuer;
            }

            return _commandLine.Issuer;
        }

        /// <summary>
        /// Return whether the server should shut down after processing one request
        /// </summary>
        /// <returns></returns>
        private Result<bool, ErrorCollection> ExitAfterRequest()
        {
            return _commandLine.ExitAfterRequest;
        }

        /// <summary>
        /// Find a certificate for a specified purpose, given a thumbprint
        /// </summary>
        /// <param name="purpose">A use for which the certificate is needed (for human consumption).</param>
        /// <param name="thumbprint">Thumbprint of the required certificate.</param>
        /// <returns>The certificate, if found; an error message otherwise.</returns>
        private Result<X509Certificate2, ErrorCollection> FindCertificate(string purpose, string thumbprint)
        {
            if (string.IsNullOrWhiteSpace(thumbprint))
            {
                return ErrorCollection.Create($"No thumbprint supplied; unable to find a {purpose} certificate.");
            }

            var certificateThumbprint = new CertificateThumbprint(thumbprint);
            return _certificateStore.FindByThumbprint(purpose, certificateThumbprint);
        }
    }
}
