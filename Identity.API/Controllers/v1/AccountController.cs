using Identity.Application.Command.ChangePw;
using Identity.Application.Command.ConfirmEmail;
using Identity.Application.Command.Login;
using Identity.Application.Command.Logout;
using Identity.Application.Command.LogoutAll;
using Identity.Application.Command.RefreshToken;
using Identity.Application.Command.RegisterUser;
using Identity.Application.Command.RevocationLogin;
using Identity.Application.Queries.ConfirmForgetPwOtp;
using Identity.Application.Queries.ForgetPassword;
using Identity.Application.Queries.GetAllInfoLogins;
using Identity.Application.Queries.ResendConfirmationEmail;
using Identity.Contract.Authentication;
using Identity.Contract.Authentication.Reponse;
using Identity.Contract.Authentication.Request;
using MapsterMapper;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Identity.Application.Command.RefreshTokenGoogle;
using Identity.Application.Command.LoginGoogle;
using Asp.Versioning;
using Microsoft.AspNetCore.RateLimiting;

namespace Identity.API.Controllers.v1
{
    [ApiVersion(1.0)]
    public class AccountController : ApiController
    {
        private readonly ISender _mediator;
        private readonly IMapper _mapper;

        public AccountController(ISender mediator, IMapper mapper)
        {
            _mediator = mediator;
            _mapper = mapper;
        }
        [HttpPost("register")]
        public async Task<IActionResult> PostRegister([FromBody] RegisterRequest request)
        {
            var command = _mapper.Map<RegisterUserCommand>(request);

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<RegisterReponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpPost("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string key, [FromBody] ConfirmEmailRequest otp)
        {
            var command = _mapper.Map<ConfirmEmailCommand>((key, otp));

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<ConfirmEmailResponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpPost("resend-confirmation-email")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequest request)
        {
            var query = _mapper.Map<ResendConfirmationEmailQuery>(request);

            var result = await _mediator.Send(query);

            return result.Match(
                result => Ok(_mapper.Map<RegisterReponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpPost("forget-password")]
        public async Task<IActionResult> ForgetPassword([FromBody] ForgetPasswordRequest request)
        {
            var query = _mapper.Map<ForgetPasswordQuery>(request);

            var result = await _mediator.Send(query);

            return result.Match(
                result => Ok(_mapper.Map<ForgetPasswordResponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpPost("confirm-forget-pw")]
        public async Task<IActionResult> ConfirmForgetPwOtp([FromQuery] string key, [FromBody] ConfirmForgetPwRequest request)
        {
            var query = _mapper.Map<ConfirmForgetPwOtpQuery>((key, request));

            var result = await _mediator.Send(query);

            return result.Match(
                result => Ok(_mapper.Map<ForgetPasswordResponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePw([FromQuery] string key, [FromQuery] string userId, [FromBody] ChangePwRequest request)
        {
            var command = _mapper.Map<ChangePwCommand>((key, userId, request));

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<ChangePwResponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var command = _mapper.Map<LoginCommand>(request);

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<LoginResponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var command = _mapper.Map<RefreshTokenCommand>(request);

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<RefreshTokenReponse>(result)),
                errors => Problem(errors)
                );
        }

        [HttpPost("logout")]
        [Authorize]
        [Authorize(Policy = "BlacklistPolicy")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
        {
            var command = _mapper.Map<LogoutCommand>(request);

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<LogoutResponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpGet("infoLogin")]
        [Authorize]
        [Authorize(Policy = "BlacklistPolicy")]
        public async Task<IActionResult> GetAllInfoLogins()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var query = new GetAllInfoLoginsQuery(userId);

            var result = await _mediator.Send(query);

            return result.Match(
                result => Ok(_mapper.Map<GetAllInfoLoginsResponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpPost("logoutAll")]
        [Authorize]
        [Authorize(Policy = "BlacklistPolicy")]
        public async Task<IActionResult> LogoutAll()
        {
            var authorizationHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer ") || string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var accessToken = authorizationHeader.Substring("Bearer ".Length).Trim();

            var command = new LogoutAllCommand(accessToken, userId);

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<LogoutResponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpPost("revocation_login")]
        [Authorize]
        [Authorize(Policy = "BlacklistPolicy")]
        public async Task<IActionResult> RevocationLogin(RevocationLoginRequest request)
        {
            var authorizationHeader = HttpContext.Request.Headers["Authorization"].FirstOrDefault();
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer ") || string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var accessToken = authorizationHeader.Substring("Bearer ".Length).Trim();

            var command = _mapper.Map<RevocationLoginCommand>((userId, accessToken, request));

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<RevocationLoginReponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpGet("login-google")]
        public IActionResult Login()
        {
            var clientId = "54512677689-2fi560s0sleddn285cmaaa7vjr6fcrhl.apps.googleusercontent.com";
            var clientSecret = "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";
            var redirectUri = "https://localhost:7100/api/v1/Account/signin-google";
            var url = $"https://accounts.google.com/o/oauth2/auth" +
                      $"?response_type=code" +
                      $"&client_id={clientId}" +
                      $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                      $"&scope=openid%20profile%20email" +
                      $"&access_type=offline";

            return Redirect(url);
        }

        [HttpGet("signin-google")]
        public async Task<IActionResult> Callback()
        {
            var authorizationCode = HttpContext.Request.Query["code"].ToString();

            if (string.IsNullOrEmpty(authorizationCode))
            {
                return BadRequest("Authorization code is missing.");
            }

            LoginGoogleCommand command = new(authorizationCode);

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<LoginResponse>(result)),
                errors => Problem(errors)
                );

        }
        [HttpPost("refresh-google")]
        public async Task<IActionResult> RefreshGoogle([FromBody] RefreshGoogleRequest request)
        {
            var command = _mapper.Map<RefreshTokenGoogleCommand>(request);

            var result = await _mediator.Send(command);

            return result.Match(
                result => Ok(_mapper.Map<RefreshTokenReponse>(result)),
                errors => Problem(errors)
                );
        }
        [HttpGet("get-demo")]
        [EnableRateLimiting("fixed")]
        public async Task<IActionResult> getdemo()
        {
            var a = 5;
            return Ok(a);
        }
    }
}
