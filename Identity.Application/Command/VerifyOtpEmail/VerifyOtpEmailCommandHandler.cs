using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using MediatR;
using System.Text.Json;

namespace Identity.Application.Command.VerifyOtpEmail
{
    public record OtpVerify(string otpHasher, string status);
    public class VerifyOtpEmailCommandHandler : IRequestHandler<VerifyOtpEmailCommand, ErrorOr<VerifyOtpEmailResult>>
    {
        private readonly IOTPService _oTPService;
        private readonly ISendOtpService _sendOtpService;
        public VerifyOtpEmailCommandHandler(IOTPService oTPService, ISendOtpService sendOtpService)
        {
            _oTPService = oTPService;
            _sendOtpService = sendOtpService;
        }
        public async Task<ErrorOr<VerifyOtpEmailResult>> Handle(VerifyOtpEmailCommand request, CancellationToken cancellationToken)
        {
            var email = request.Email;
            var otp = request.Otp;

            var otpHasher = await _sendOtpService.GetCachedReponseAsync(email);

            if (string.IsNullOrEmpty(otpHasher))
            {
                return Errors.Otp.OtpInvalid;
            }

            var otpVerify = JsonSerializer.Deserialize<OtpVerify>(otpHasher);

            if (!_oTPService.VerifyOTP(otp, otpVerify.otpHasher))
            {
                return Errors.Otp.OtpInvalid;
            }

            var obj = new Dictionary<string, string>();
            obj.Add("otpHasher", otpVerify.otpHasher);
            obj.Add("status", "true");

            await _sendOtpService.SetCacheReponseAsync(request.Email, obj, TimeSpan.FromSeconds(300));

            return new VerifyOtpEmailResult(email, "Verify otp success");


        }
    }
}
