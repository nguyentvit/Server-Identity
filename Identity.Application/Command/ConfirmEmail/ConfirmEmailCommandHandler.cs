using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using Identity.Domain.Common.Models;
using Identity.Domain.Identity;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Identity.Application.Command.ConfirmEmail
{
    public class ConfirmEmailCommandHandler : IRequestHandler<ConfirmEmailCommand, ErrorOr<ConfirmEmailResult>>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITokenProvider _tokenProvider;
        private readonly IUnitOfWork _unitOfWork;
        public ConfirmEmailCommandHandler(UserManager<ApplicationUser> userManager, ITokenProvider tokenProvider, IUnitOfWork unitOfWork)
        {
            _userManager = userManager;
            _tokenProvider = tokenProvider;
            _unitOfWork = unitOfWork;
        }

        public async Task<ErrorOr<ConfirmEmailResult>> Handle(ConfirmEmailCommand request, CancellationToken cancellationToken)
        {
            var hashedKey = request.hashedUserId;
            var otp = request.Otp;

            var userId = _tokenProvider.ValidateTokenEmailConfirmationToken(hashedKey);

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return Errors.User.NotFoundUser;
            }

            var result = _userManager.ConfirmEmailAsync(user, otp);

            if (result.Result.Succeeded)
            {
                ConfirmEmailUserResult confirmEmailUserResult = new(user.Id, user.Email, true);
                ConfirmEmailResult confirmEmailResult = new("success", "Email confirmed successfully", confirmEmailUserResult);

                int count = await _unitOfWork.SaveChangesAsync();
                return confirmEmailResult;
            }

            return Errors.Otp.OtpInvalid;
        }
    }
}
