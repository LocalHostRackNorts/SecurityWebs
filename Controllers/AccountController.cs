using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using SecurityWebs.Models;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;

namespace SecurityWebs.Controllers
{
    [ApiController]
    [Route("Account")]
    public class AccountController : Controller
    {

        private readonly IConfiguration _configuration;

        public AccountController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("Login")]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(AuthModel model)
        {
            if (ModelState.IsValid)
            {
                string domain = _configuration["ActiveDirectory:Domain"];
                string[] groups = _configuration.GetSection("ActiveDirectory:Groups").Get<string[]>();

                using (PrincipalContext context = new(ContextType.Domain, domain, model.SamAccountName, model.Password))
                {
                    bool isAuthenticated = context.ValidateCredentials(model.SamAccountName, model.Password);

                    if (isAuthenticated)
                    {
                        bool isMemberOfAnyGroup = false;

                        foreach (string group in groups)
                        {
                            GroupPrincipal groupPrincipal = await FindGroup(context, group);

                            if (groupPrincipal != null && groupPrincipal.Members.Any(member => member.SamAccountName.Equals(model.SamAccountName, StringComparison.OrdinalIgnoreCase)))
                            {
                                isMemberOfAnyGroup = true;
                                break;
                            }
                        }

                        if (isMemberOfAnyGroup)
                        {
                            ClaimsIdentity identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
                            identity.AddClaim(new Claim(ClaimTypes.Name, model.SamAccountName));

                            ClaimsPrincipal principal = new ClaimsPrincipal(identity);

                            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                            return RedirectToAction("Index", "Home");
                        }
                    }
                }

                ModelState.AddModelError(string.Empty, "Autenticación fallida");
            }

            return View(model);
        }

        [HttpPost("Logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        private async Task<GroupPrincipal> FindGroup(PrincipalContext context, string groupName)
        {
            using (var searcher = new PrincipalSearcher(new GroupPrincipal(context) { Name = groupName }))
            {
                var group = searcher.FindAll().FirstOrDefault() as GroupPrincipal;
                return await Task.FromResult(group);
            }
        }

    }
}
