using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace xCorporate.Service
{
    public class AuthenticationService : AuthenticationStateProvider
    {
        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {  
            //Esto equivale a cerrar session
            var user = new ClaimsPrincipal();
            return Task.FromResult(new AuthenticationState(user));
        }

        public void Ingresar(string iduser) {
            var identity = new ClaimsIdentity(new[]
          {
                new Claim(ClaimTypes.Name, iduser)
            }, "auth");
            var user = new ClaimsPrincipal(identity);
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
        }
    }
}
