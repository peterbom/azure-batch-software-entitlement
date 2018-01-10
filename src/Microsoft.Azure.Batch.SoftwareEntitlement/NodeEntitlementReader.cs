using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using Microsoft.Azure.Batch.SoftwareEntitlement.Common;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Azure.Batch.SoftwareEntitlement
{
    public class NodeEntitlementReader
    {
        private readonly string _expectedAudience;
        private readonly string _expectedIssuer;

        /// <summary>
        /// Gets the key that should have been used to sign the token
        /// </summary>
        public SecurityKey SigningKey { get; }

        /// <summary>
        /// Gets the credentials that should have been used to encrypt the token
        /// </summary>
        public SecurityKey EncryptionKey { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenReader"/> class
        /// </summary>
        /// <param name="signingKey">Optional key to use when verifying the signature of the token.</param> 
        /// <param name="encryptingKey">Optional key to use when decrypting the token.</param> 
        public NodeEntitlementReader(
            string expectedAudience,
            string expectedIssuer,
            SecurityKey signingKey = null,
            SecurityKey encryptingKey = null)
        {
            _expectedAudience = expectedAudience;
            _expectedIssuer = expectedIssuer;

            SigningKey = signingKey;
            EncryptionKey = encryptingKey;
        }

        public Errorable<NodeEntitlements> ReadFromToken(string tokenString)
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = _expectedAudience,
                ValidateIssuer = true,
                ValidIssuer = _expectedIssuer,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                RequireSignedTokens = SigningKey != null,
                ClockSkew = TimeSpan.FromSeconds(60),
                IssuerSigningKey = SigningKey,
                ValidateIssuerSigningKey = true,
                TokenDecryptionKey = EncryptionKey
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var principal = handler.ValidateToken(tokenString, validationParameters, out var token);

                // Set standard claims from token: NotBefore, NotAfter and Issuer
                var result = new NodeEntitlements()
                    .FromInstant(new DateTimeOffset(token.ValidFrom))
                    .UntilInstant(new DateTimeOffset(token.ValidTo))
                    .WithIssuer(token.Issuer);

                // We don't expect multiple audiences to appear in the token
                var audience = (token as JwtSecurityToken)?.Audiences?.SingleOrDefault();
                if (audience != null)
                {
                    result = result.WithAudience(audience);
                }

                var virtualMachineIdClaim = principal.FindFirst(Claims.VirtualMachineId);
                if (virtualMachineIdClaim != null)
                {
                    result = result.WithVirtualMachineId(virtualMachineIdClaim.Value);
                }

                var cpuCoreCountClaim = principal.FindFirst(Claims.CpuCoreCount);
                if (cpuCoreCountClaim != null && int.TryParse(cpuCoreCountClaim.Value, out int maxCpuCoreCount))
                {
                    result = result.WithCpuCoreCount(maxCpuCoreCount);
                }

                foreach (var applicationClaim in principal.FindAll(Claims.Application))
                {
                    result = result.AddApplication(applicationClaim.Value);
                }

                foreach (var ipClaim in principal.FindAll(Claims.IpAddress))
                {
                    if (IPAddress.TryParse(ipClaim.Value, out var parsedAddress))
                    {
                        result = result.AddIpAddress(parsedAddress);
                    }
                    else
                    {
                        return InvalidTokenError($"Invalid IP claim: {ipClaim.Value}");
                    }
                }

                var entitlementIdClaim = principal.FindFirst(Claims.EntitlementId);
                if (entitlementIdClaim != null)
                {
                    result = result.WithIdentifier(entitlementIdClaim.Value);
                }

                var batchAccountIdClaim = principal.FindFirst(Claims.BatchAccountId);
                if (batchAccountIdClaim != null)
                {
                    result = result.WithBatchAccountId(batchAccountIdClaim.Value);
                }

                var poolIdClaim = principal.FindFirst(Claims.PoolId);
                if (poolIdClaim != null)
                {
                    result = result.WithPoolId(poolIdClaim.Value);
                }

                var jobIdClaim = principal.FindFirst(Claims.JobId);
                if (jobIdClaim != null)
                {
                    result = result.WithJobId(jobIdClaim.Value);
                }

                var taskIdClaim = principal.FindFirst(Claims.TaskId);
                if (taskIdClaim != null)
                {
                    result = result.WithTaskId(taskIdClaim.Value);
                }

                return Errorable.Success(result);
            }
            catch (SecurityTokenNotYetValidException exception)
            {
                return TokenNotYetValidError(exception.NotBefore);
            }
            catch (SecurityTokenExpiredException exception)
            {
                return TokenExpiredError(exception.Expires);
            }
            catch (SecurityTokenException exception)
            {
                return InvalidTokenError(exception.Message);
            }
        }

        private static Errorable<NodeEntitlements> TokenNotYetValidError(DateTime notBefore)
        {
            var timestamp = notBefore.ToString(TimestampParser.ExpectedFormat);
            return Errorable.Failure<NodeEntitlements>($"Token will not be valid until {timestamp}");
        }

        private static Errorable<NodeEntitlements> TokenExpiredError(DateTime expires)
        {
            var timestamp = expires.ToString(TimestampParser.ExpectedFormat);
            return Errorable.Failure<NodeEntitlements>($"Token expired at {timestamp}");
        }

        private static Errorable<NodeEntitlements> InvalidTokenError(string reason)
        {
            return Errorable.Failure<NodeEntitlements>(
                $"Invalid token ({reason})");
        }
    }
}
