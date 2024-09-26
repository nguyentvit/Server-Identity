using Identity.Application.Common.Persistence;
using Identity.Application.DomainEvents;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Identity;
using Identity.Infrastructure.Persistence;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Identity.Infrastructure.Services
{
    public class CustomUserManager : UserManager<ApplicationUser>
    {
        private readonly IPublisher _mediator;
        private readonly IOTPService _oTPService;
        private readonly IOTPQueryRepository _otpQueryRepository;
        private readonly ITokenProvider _tokenProvider;
        private readonly IdentityDbContext _dbContext;
        public CustomUserManager(
        IUserStore<ApplicationUser> store,
        IOptions<IdentityOptions> optionsAccessor,
        IPasswordHasher<ApplicationUser> passwordHasher,
        IEnumerable<IUserValidator<ApplicationUser>> userValidators,
        IEnumerable<IPasswordValidator<ApplicationUser>> passwordValidators,
        ILookupNormalizer keyNormalizer,
        IdentityErrorDescriber errors,
        IServiceProvider services,
        ILogger<UserManager<ApplicationUser>> logger,
        IMediator mediator,
        IOTPService oTPService,
        IOTPQueryRepository oTPQueryRepository,
        ITokenProvider tokenProvider,
        IdentityDbContext identityDbContext)
        : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
            _mediator = mediator;
            _oTPService = oTPService;
            _otpQueryRepository = oTPQueryRepository;
            _tokenProvider = tokenProvider;
            _dbContext = identityDbContext;
        }
        public override async Task<IdentityResult> CreateAsync(ApplicationUser user, string password)
        {
            user.UserName = user.Email;

            user.EmailConfirmed = true;
            var result = await base.CreateAsync(user, password);

            //if (result.Succeeded)
            //{
            //    await _mediator.Publish(new UserCreatedDomainEvent(user.Id, user.Email));
            //}
            return result;
        }
        public override async Task<IdentityResult> ConfirmEmailAsync(ApplicationUser user, string token)
        {
            var otp = _otpQueryRepository.GetUnusedOtpByUserId(user.Id);
            if (otp == null)
            {
                return IdentityResult.Failed(ErrorDescriber.InvalidToken());
            }
            var verifyOtp = _oTPService.VerifyOTP(token, otp.Code);
            if (!verifyOtp)
            {
                return IdentityResult.Failed(ErrorDescriber.InvalidToken());
            }
            await _mediator.Publish(new ConfirmEmailDomainEvent(user.Id));

            user.EmailConfirmed = true;

            await Store.UpdateAsync(user, CancellationToken.None);

            return IdentityResult.Success;
        }
        public override async Task<IdentityResult> ResetPasswordAsync(ApplicationUser user, string token, string newPassword)
        {
            var trackedUser = _dbContext.Users.Local.FirstOrDefault(u => u.Id == user.Id);
            if (trackedUser != null)
            {
                // Nếu đã theo dõi, sử dụng thực thể này
                user = trackedUser;
            }
            else
            {
                // Nếu chưa theo dõi, đính kèm thực thể mới
                _dbContext.Users.Attach(user);
            }
            var result = await base.ResetPasswordAsync(user, token, newPassword);

            if (result.Succeeded)
            {
                return IdentityResult.Success;
            }

            return IdentityResult.Failed(ErrorDescriber.InvalidToken());
        }
        public override async Task<string> GenerateEmailConfirmationTokenAsync(ApplicationUser user)
        {
            await Task.CompletedTask;
            return _tokenProvider.GenerateEmailConfirmationToken(user);
        }
        public override async Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user)
        {
            await Task.CompletedTask;
            await _mediator.Publish(new DisableOTPPwDomainEvent(user.Id));

            return _tokenProvider.GenerateResetPwToken(user);
        }
        public override async Task<bool> VerifyUserTokenAsync(ApplicationUser user, string tokenProvider, string purpose, string token)
        {
            await Task.CompletedTask;

            if (purpose == "ResetPassword")
            {
                var userId = _tokenProvider.ValidateResetPasswordToken(token);
                return userId == user.Id;
            }

            if (purpose == "EmailConfirmation")
            {
                var userId = _tokenProvider.ValidateTokenEmailConfirmationToken(token);
                return userId == user.Id;
            }

            return false;
        }
    }
}
