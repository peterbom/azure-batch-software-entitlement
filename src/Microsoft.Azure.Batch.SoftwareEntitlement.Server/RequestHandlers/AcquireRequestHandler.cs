using System;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Batch.SoftwareEntitlement.Common;
using Microsoft.Azure.Batch.SoftwareEntitlement.Server.Model;
using Microsoft.Extensions.Logging;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Server.RequestHandlers
{
    public class AcquireRequestHandler : RequestHandlerBase, IRequestHandler<AcquireRequestBody>
    {
        private readonly TokenVerifier _verifier;
        private readonly EntitlementStore _entitlementStore;

        public AcquireRequestHandler(
            ILogger logger,
            TokenVerifier tokenVerifier,
            EntitlementStore entitlementStore) : base(logger)
        {
            _verifier = tokenVerifier;
            _entitlementStore = entitlementStore;
        }

        public Response Handle(
            HttpContext httpContext,
            AcquireRequestBody requestContext)
        {
            var remoteIpAddress = httpContext.Connection.RemoteIpAddress;

            return ParseDuration(requestContext)
                .OnOk(duration => ExtractVerificationRequest(requestContext, remoteIpAddress).OnOk(extracted => new
                {
                    Duration = duration,
                    Extracted = extracted
                }))
                .OnOk(x => Verify(x.Extracted.Request, x.Extracted.Token).OnOk(tokenProperties => new
                {
                    x.Duration,
                    x.Extracted,
                    TokenProperties = tokenProperties
                }))
                .OnOk(x =>
                {
                    var entitlementId = CreateEntitlementId();
                    var acquisitionTime = DateTime.UtcNow;
                    var expiry = acquisitionTime.Add(x.Duration);
                    StoreEntitlement(entitlementId, x.TokenProperties, acquisitionTime);
                    return CreateSuccessResponse(entitlementId, expiry);
                })
                .Merge();
        }

        private Result<TimeSpan, Response> ParseDuration(AcquireRequestBody body) =>
            body.Duration
                .ParseDuration()
                .OnError(CreateBadRequestResponse);

        private Result<(TokenVerificationRequest Request, string Token), Response> ExtractVerificationRequest(
            IVerificationRequestBody body,
            IPAddress remoteIpAddress) =>
            body.ExtractVerificationRequest(remoteIpAddress, Logger)
                .OnError(CreateBadRequestResponse);

        private Result<EntitlementTokenProperties, Response> Verify(
            TokenVerificationRequest request,
            string token) =>
            _verifier.Verify(request, token)
                .OnError(errors => CreateDeniedResponse(errors, request.ApplicationId));

        private static string CreateEntitlementId() => Guid.NewGuid().ToString("N");

        private EntitlementProperties StoreEntitlement(
            string entitlementId,
            EntitlementTokenProperties tokenProperties,
            DateTime acquisitionTime) =>
            _entitlementStore.StoreEntitlement(entitlementId, tokenProperties, acquisitionTime);

        private static Response CreateSuccessResponse(
            string entitlementId,
            DateTime expiryTime)
        {
            var value = new AcquireSuccessResponse(entitlementId, expiryTime);
            return Response.CreateSuccess(value);
        }
    }
}
