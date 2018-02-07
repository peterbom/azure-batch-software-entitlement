using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using Microsoft.Azure.Batch.SoftwareEntitlement.Common;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Azure.Batch.SoftwareEntitlement
{
    public class NodeEntitlementReader
    {
        private readonly string _expectedAudience;
        private readonly string _expectedIssuer;
        private readonly SecurityKey _signingKey;
        private readonly SecurityKey _encryptionKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenReader"/> class
        /// </summary>
        /// <param name="expectedAudience">The audience claim that tokens to be read are expected to have.</param>
        /// <param name="expectedIssuer">The issuer claim that tokens to be read are expected to have.</param>
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
            _signingKey = signingKey;
            _encryptionKey = encryptingKey;
        }

        public Errorable<NodeEntitlements> ReadFromToken(string tokenString)
        {
            return ParseToken(tokenString)
                .Bind(parsed => ReadClaims(parsed.Principal, parsed.Token));
        }

        private Errorable<(ClaimsPrincipal Principal, SecurityToken Token)> ParseToken(string tokenString)
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = _expectedAudience,
                ValidateIssuer = true,
                ValidIssuer = _expectedIssuer,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                RequireSignedTokens = _signingKey != null,
                ClockSkew = TimeSpan.FromSeconds(60),
                IssuerSigningKey = _signingKey,
                ValidateIssuerSigningKey = true,
                TokenDecryptionKey = _encryptionKey
            };

            Errorable<(ClaimsPrincipal Principal, SecurityToken Token)> Failure(string error)
                => Errorable.Failure<(ClaimsPrincipal Principal, SecurityToken Token)>(error);

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var principal = handler.ValidateToken(tokenString, validationParameters, out var token);

                return Errorable.Success((Principal: principal, Token: token));
            }
            catch (SecurityTokenNotYetValidException exception)
            {
                return Failure(TokenNotYetValidError(exception.NotBefore));
            }
            catch (SecurityTokenExpiredException exception)
            {
                return Failure(TokenExpiredError(exception.Expires));
            }
            catch (SecurityTokenException exception)
            {
                return Failure(InvalidTokenError(exception.Message));
            }
        }

        private static Errorable<NodeEntitlements> ReadClaims(ClaimsPrincipal principal, SecurityToken token)
        {
            var jwt = token as JwtSecurityToken;

            NodeEntitlements SetAudience(NodeEntitlements entitlement)
            {
                // We don't expect multiple audiences to appear in the token
                var audience = jwt?.Audiences?.SingleOrDefault();
                return audience != null
                    ? entitlement.WithAudience(audience)
                    : entitlement;
            }

            NodeEntitlements SetIssuedAt(NodeEntitlements entitlement)
            {
                var iat = jwt?.Payload.Iat;
                return iat.HasValue
                    ? entitlement.WithIssuedAt(EpochTime.DateTime(iat.Value))
                    : entitlement;
            }

            Errorable<string> OptionalClaim(string claimType)
            {
                return OptionalErrorableClaim(claimType, val => Errorable.Success(val));
            }

            Errorable<T> OptionalErrorableClaim<T>(string claimType, Func<string, Errorable<T>> parseValue)
            {
                var claim = principal.FindFirst(claimType);
                if (claim != null)
                {
                    return parseValue(claim.Value);
                }

                return Errorable.Success<T>(default);
            }

            Errorable<IEnumerable<string>> MultipleClaims(string claimType)
            {
                return MultipleErrorableClaims(claimType, val => Errorable.Success(val));
            }

            Errorable<IEnumerable<T>> MultipleErrorableClaims<T>(string claimType, Func<string, Errorable<T>> parseValue)
            {
                var valueResults = principal.FindAll(claimType).Select(claim => parseValue(claim.Value));
                return valueResults.Reduce();
            }

            return Errorable.Success(new NodeEntitlements())
                .Bind(e => e.FromInstant(new DateTimeOffset(token.ValidFrom)))
                .Bind(e => e.UntilInstant(new DateTimeOffset(token.ValidTo)))
                .Bind(e => e.WithIssuer(token.Issuer))
                .Bind(SetAudience)
                .Bind(SetIssuedAt)
                .Configure(MultipleClaims(Claims.Application), (e, vals) => e.WithApplications(vals))
                .Configure(MultipleErrorableClaims(Claims.IpAddress, ParseIpAddresses), (e, vals) => e.WithIpAddresses(vals))
                .Configure(OptionalClaim(Claims.VirtualMachineId), (e, val) => e.WithVirtualMachineId(val))
                .Configure(OptionalClaim(Claims.EntitlementId), (e, val) => e.WithIdentifier(val))
                .Configure(OptionalErrorableClaim(Claims.CpuCoreCount, ParseCpuCoreCount), (e, val) => e.WithCpuCoreCount(val))
                .Configure(OptionalClaim(Claims.BatchAccountId), (e, val) => e.WithBatchAccountId(val))
                .Configure(OptionalClaim(Claims.PoolId), (e, val) => e.WithPoolId(val))
                .Configure(OptionalClaim(Claims.JobId), (e, val) => e.WithJobId(val))
                .Configure(OptionalClaim(Claims.TaskId), (e, val) => e.WithTaskId(val));
        }

        private static Errorable<int> ParseCpuCoreCount(string value)
        {
            return int.TryParse(value, out int cpuCoreCount)
                ? Errorable.Success(cpuCoreCount)
                : Errorable.Failure<int>(InvalidTokenError($"Invalid CPU core count claim: {value}"));
        }

        private static Errorable<IPAddress> ParseIpAddresses(string value)
        {
            return IPAddress.TryParse(value, out var parsedAddress)
                ? Errorable.Success(parsedAddress)
                : Errorable.Failure<IPAddress>(InvalidTokenError($"Invalid IP claim: {value}"));
        }

        private static string TokenNotYetValidError(DateTime notBefore)
        {
            var timestamp = notBefore.ToString(TimestampParser.ExpectedFormat, CultureInfo.InvariantCulture);
            return $"Token will not be valid until {timestamp}";
        }

        private static string TokenExpiredError(DateTime expires)
        {
            var timestamp = expires.ToString(TimestampParser.ExpectedFormat, CultureInfo.InvariantCulture);
            return $"Token expired at {timestamp}";
        }

        private static string InvalidTokenError(string reason)
        {
            return $"Invalid token ({reason})";
        }
    }
}
