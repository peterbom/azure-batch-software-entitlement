using System;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Batch.SoftwareEntitlement.Common;
using Microsoft.Azure.Batch.SoftwareEntitlement.Server.Model;
using Microsoft.Extensions.Logging;

namespace Microsoft.Azure.Batch.SoftwareEntitlement.Server.RequestHandlers
{
    public class RenewRequestHandler : RequestHandlerBase, IRequestHandler<(RenewRequestBody Body, string EntitlementId)>
    {
        private readonly EntitlementStore _entitlementStore;

        public RenewRequestHandler(
            ILogger logger,
            EntitlementStore entitlementStore) : base(logger)
        {
            _entitlementStore = entitlementStore;
        }

        public Response Handle(
            HttpContext httpContext,
            (RenewRequestBody Body, string EntitlementId) requestContext)
        {
            var entitlementId = requestContext.EntitlementId;

            return ParseDuration(requestContext.Body)
                .OnOk(duration => FindEntitlement(entitlementId)
                    .OnOk(CheckNotReleased)
                    .OnOk(entitlement => new
                    {
                        Duration = duration,
                        Entitlement = entitlement
                    }))
                .OnOk(x =>
                {
                    var renewalTime = DateTime.UtcNow;
                    var expiry = renewalTime.Add(x.Duration);
                    return StoreRenewal(entitlementId, renewalTime).OnOk(_ => CreateSuccessResponse(expiry));
                })
                .Merge();
        }

        private Result<TimeSpan, Response> ParseDuration(RenewRequestBody body) =>
            body.Duration
                .ParseDuration()
                .OnError(CreateBadRequestResponse);

        private Result<EntitlementProperties, Response> FindEntitlement(string entitlementId) =>
            _entitlementStore.FindEntitlement(entitlementId)
                .OnError(errors => CreateNotFoundResponse(entitlementId));

        private Result<EntitlementProperties, Response> CheckNotReleased(EntitlementProperties entitlementProperties)
        {
            if (entitlementProperties.IsReleased)
            {
                return CreateAlreadyReleasedResponse(entitlementProperties.EntitlementId);
            }

            return entitlementProperties;
        }

        private Result<EntitlementProperties, Response> StoreRenewal(string entitlementId, DateTime renewalTime) =>
            _entitlementStore.RenewEntitlement(entitlementId, renewalTime)
                .OnError(CreateInternalErrorResponse);

        private static Response CreateSuccessResponse(DateTime expiryTime)
        {
            var value = new RenewSuccessResponse(expiryTime);
            return Response.CreateSuccess(value);
        }
    }
}
