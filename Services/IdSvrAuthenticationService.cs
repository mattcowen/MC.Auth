using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Orchard.Mvc;
using Orchard.Security;

namespace MC.Auth.Services
{
    public class IdSvrAuthenticationService: IAuthenticationService {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IMembershipService _membershipService;

        public IdSvrAuthenticationService(IHttpContextAccessor httpContextAccessor, IMembershipService membershipService)
        {
            _httpContextAccessor = httpContextAccessor;
            _membershipService = membershipService;
        }

        public void SignIn(IUser user, bool createPersistentCookie) {}

        public void SignOut() {}

        public void SetAuthenticatedUserForRequest(IUser user) { }

        public IUser GetAuthenticatedUser() {
            var azureUser = _httpContextAccessor.Current().GetOwinContext().Authentication.User;

            if (!azureUser.Identity.IsAuthenticated) {
                return null;
            }

            var userName = azureUser.Identity.Name.Trim();

            var localUser = _membershipService.GetUser(userName);

            return localUser;
        }
    }

}