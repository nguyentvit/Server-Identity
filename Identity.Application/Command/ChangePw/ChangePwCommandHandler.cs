using ErrorOr;
using Identity.Application.Common.Persistence;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using Identity.Domain.Common.Models;
using Identity.Domain.Identity;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Identity.Application.Command.ChangePw
{
    public class ChangePwCommandHandler : IRequestHandler<ChangePwCommand, ErrorOr<ChangePwResult>>
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IApplicationUserQueryRepository _userQueryRepository;
        private readonly IUnitOfWork _unitOfWork;
        private readonly UserManager<ApplicationUser> _userManager;
        public ChangePwCommandHandler(ITokenProvider tokenProvider, IApplicationUserQueryRepository userQueryRepository, IUnitOfWork unitOfWork, UserManager<ApplicationUser> userManager)
        {
            _tokenProvider = tokenProvider;
            _userQueryRepository = userQueryRepository;
            _unitOfWork = unitOfWork;
            _userManager = userManager;
        }

        public async Task<ErrorOr<ChangePwResult>> Handle(ChangePwCommand request, CancellationToken cancellationToken)
        {
            var key = request.Key;
            var password = request.Password;
            var userIdHashed = request.UserId;

            var userId = _tokenProvider.ValidateResetPasswordToken(userIdHashed);
            var user = _userQueryRepository.GetUserByUserId(userId);

            if (user == null)
            {
                return Errors.User.NotFoundUser;
            }

            var result = await _userManager.ResetPasswordAsync(user, key, password);

            if (result.Succeeded)
            {
                var message = "Your password has been successfully changed. You can now log in with your new password.";
                ChangePwResult changePwResult = new("success", message);
                return changePwResult;
            }

            return Errors.Otp.OtpInvalid;

            
        }
    }
}
