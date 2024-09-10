using ErrorOr;
using Identity.Application.Common;
using Identity.Application.Common.Results;
using Identity.Application.Data;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using Identity.Domain.Common.Models;
using Identity.Domain.Identity;
using MediatR;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Text;


namespace Identity.Application.Command.RegisterUser
{
    public class RegisterUserCommandHandler : IRequestHandler<RegisterUserCommand, ErrorOr<RegisterResult>>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITokenProvider _tokenProvider;
        private readonly IUnitOfWork _unitOfWork;
        public RegisterUserCommandHandler(UserManager<ApplicationUser> userManager, ITokenProvider tokenProvider, IUnitOfWork unitOfWork)
        {
            _userManager = userManager;
            _tokenProvider = tokenProvider;
            _unitOfWork = unitOfWork;
        }
        public async Task<ErrorOr<RegisterResult>> Handle(RegisterUserCommand request, CancellationToken cancellationToken)
        {
            if (await _userManager.FindByEmailAsync(request.Email) is not null)
            {
                return Errors.User.DuplicateEmail;
            }

            ApplicationUser user = new()
            {
                Email = request.Email,
                UserName = request.Email,
                PhoneNumber = request.PhoneNumber,
                Name = request.Name,
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            var count = await _unitOfWork.SaveChangesAsync();

            if (result.Succeeded)
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, user.Name),
                    new Claim(ClaimTypes.Role, IdentityConfig.Customer)
                };

                await _userManager.AddToRoleAsync(user, IdentityConfig.Customer);
                await _userManager.AddClaimsAsync(user, claims);

                var key = _tokenProvider.GenerateEmailConfirmationToken(user);
                var confirmUrl = $"https://localhost:7100/api/v1/Account/confirmEmail/?key={key}";

                RegisterDataResult data = new(user.Email, user.Id, user.UserName, confirmUrl);
                RegisterResult registerResult = new(true, "Registration successful. Please check your email to confirm your account.", data);

                return registerResult;
            }

            return Errors.User.RegiterError;
        }
    }
}
