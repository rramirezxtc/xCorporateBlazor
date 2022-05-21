using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Newtonsoft.Json;
using System.Configuration;
using System.Security.Claims;
using xCorporate.Data;

namespace xCorporate.Service
{
    public class AuthenticationService : AuthenticationStateProvider
    {
        private Usuario usuario { get; set; }
        private readonly ProtectedSessionStorage _sessionStorage;
        private readonly IConfiguration _configuration;

        public AuthenticationService(ProtectedSessionStorage sessionStorage, IConfiguration configuration)
        {
            _sessionStorage = sessionStorage;
            _configuration = configuration;
        }
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            Usuario userSession = await GetUserSession();

            if (userSession != null)
                return await GenerateAuthenticationState(userSession);
            return await GenerateEmptyAuthenticationState();
        }

        public async Task<Usuario> GetUserSession()
        {
            if (usuario != null)
                return usuario;

            var localUserJson = await _sessionStorage.GetAsync<string>(_configuration["MyKeyUserNameSession"]);
            if (!localUserJson.Success)
                return null;

            try
            {
                return RefreshUserSession(JsonConvert.DeserializeObject<Usuario>(localUserJson.Value));
            }
            catch
            {
                await LogoutAsync();
                return null;
            }
        }

        private Task<AuthenticationState> GenerateAuthenticationState(Usuario user)
        {
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, user.Username.ToString())
            }, "apiauth_type");

            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            return Task.FromResult(new AuthenticationState(claimsPrincipal));
        }

        public async Task LoginAsync(Usuario user)
        {
            await SetUserSession(user);
            NotifyAuthenticationStateChanged(GenerateAuthenticationState(user));
        }

        public async Task LogoutAsync()
        {
            await _sessionStorage.DeleteAsync(_configuration["MyKeyUserNameSession"]);
            NotifyAuthenticationStateChanged(GenerateEmptyAuthenticationState());
        }

        private async Task SetUserSession(Usuario user)
        {
            RefreshUserSession(user);
            await _sessionStorage.SetAsync(_configuration["MyKeyUserNameSession"], JsonConvert.SerializeObject(user));
        }

        private Usuario RefreshUserSession(Usuario user) => usuario = user;

        private Task<AuthenticationState> GenerateEmptyAuthenticationState() => Task.FromResult(new AuthenticationState(new ClaimsPrincipal()));

    }
}
