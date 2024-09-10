using Dapper;
using ErrorOr;
using Identity.Application.Common.Persistence;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using Identity.Domain.Common.Models;
using Identity.Domain.Identity;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Identity.Application.Queries.ConfirmForgetPwOtp
{
    public class ConfirmForgetPwOtpQueryHandler : IRequestHandler<ConfirmForgetPwOtpQuery, ErrorOr<ForgetPasswordResult>>
    {
        private IOTPPwQueryRepository _otpPwQueryRepository;
        private ITokenProvider _tokenProvider;
        private IApplicationUserQueryRepository _userPwQueryRepository;
        private readonly IOTPService _oTPService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUnitOfWork _unitOfWork;
        public ConfirmForgetPwOtpQueryHandler(IOTPPwQueryRepository otpPwQueryRepository, ITokenProvider tokenProvider, IApplicationUserQueryRepository userPwQueryRepository, IOTPService oTPService, UserManager<ApplicationUser> userManager, IUnitOfWork unitOfWork)
        {
            _tokenProvider = tokenProvider;
            _otpPwQueryRepository = otpPwQueryRepository;
            _userPwQueryRepository = userPwQueryRepository;
            _oTPService = oTPService;
            _userManager = userManager;
            _unitOfWork = unitOfWork;
        }

        public async Task<ErrorOr<ForgetPasswordResult>> Handle(ConfirmForgetPwOtpQuery request, CancellationToken cancellationToken)
        {
            var hashedUserId = request.HashedUserId;
            var otp = request.Otp;

            var userId = _tokenProvider.ValidateTokenEmailConfirmationToken(hashedUserId);
            
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return Errors.User.NotFoundUser;
            }

            var otpPw = _otpPwQueryRepository.GetUnusedOtpByUserId(userId);

            if (otpPw == null)
            {
                return Errors.Otp.OtpInvalid;
            }

            if (!_oTPService.VerifyOTP(otp, otpPw.Code))
            {
                return Errors.Otp.OtpInvalid;
            }

            var userIdHashed = _tokenProvider.GenerateResetPwToken(user);

            var key = await _userManager.GeneratePasswordResetTokenAsync(user);
            await _unitOfWork.SaveChangesAsync();
            var confirmUrl = $"https://localhost:7100/api/v1/Account/change-password/?key={key}&userId={userIdHashed}";

            var message = "OTP verification successful. Please use the link below to reset your password.";
            ForgetPasswordResult forgetPwResult = new("success", message, user.Email, confirmUrl);

            return forgetPwResult;
        }
    }
}
