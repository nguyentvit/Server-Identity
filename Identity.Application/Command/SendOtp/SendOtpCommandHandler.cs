using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Application.DomainEvents;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using Identity.Domain.Identity;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace Identity.Application.Command.SendOtp
{
    public class SendOtpCommandHandler : IRequestHandler<SendOtpCommand, ErrorOr<SendOtpResult>>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IOTPService _oTPService;
        private readonly ISendOtpService _sendOtpService;
        private readonly IPublisher _mediator;
        private readonly IHttpContextAccessor _contextAccessor;

        public SendOtpCommandHandler(UserManager<ApplicationUser> userManager, ISendOtpService sendOtpService, IOTPService oTPService, IMediator mediator, IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _sendOtpService=sendOtpService;
            _oTPService = oTPService;
            _mediator = mediator;
            _contextAccessor = httpContextAccessor;
        }

        public async Task<ErrorOr<SendOtpResult>> Handle(SendOtpCommand request, CancellationToken cancellationToken)
        {
            
            if (await _userManager.FindByEmailAsync(request.Email) is not null)
            {
                return Errors.User.DuplicateEmail;
            }

            var otp = _oTPService.GenerateOTP();
            var otpHasher = _oTPService.HashOTP(otp);

            var obj = new Dictionary<string, string>();
            obj.Add("otpHasher", otpHasher);
            obj.Add("status", "false");

            await _sendOtpService.SetCacheReponseAsync(request.Email, obj, TimeSpan.FromSeconds(300));

            await _mediator.Publish(new SendEmailDomainEvent(request.Email, otp));

            return new SendOtpResult(request.Email, "Please check your email to confirm your email.");
        }
    }
}
