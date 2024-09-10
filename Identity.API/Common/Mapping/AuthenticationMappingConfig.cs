using Azure.Core;
using Identity.Application.Command.ChangePw;
using Identity.Application.Command.ConfirmEmail;
using Identity.Application.Command.Login;
using Identity.Application.Command.Logout;
using Identity.Application.Command.RefreshToken;
using Identity.Application.Command.RefreshTokenGoogle;
using Identity.Application.Command.RegisterUser;
using Identity.Application.Command.RevocationLogin;
using Identity.Application.Common.Results;
using Identity.Application.Queries.ConfirmForgetPwOtp;
using Identity.Application.Queries.ForgetPassword;
using Identity.Application.Queries.ResendConfirmationEmail;
using Identity.Contract.Authentication;
using Identity.Contract.Authentication.Reponse;
using Identity.Contract.Authentication.Request;
using Mapster;

namespace Identity.API.Common.Mapping
{
    public class AuthenticationMappingConfig : IRegister
    {
        public void Register(TypeAdapterConfig config)
        {
            config.NewConfig<RegisterRequest, RegisterUserCommand>()
                .Map(dest => dest, src => src);

            config.NewConfig<RegisterResult, RegisterReponse>()
                .Map(dest => dest.success, src => src.success)
                .Map(dest => dest.message, src => src.message)
                .Map(dest => dest.data, src => src.data);

            config.NewConfig<RegisterDataResult, RegisterDataReponse>()
                .Map(dest => dest.email, src => src.email)
                .Map(dest => dest.userId, src => src.userId)
                .Map(dest => dest.userName, src => src.userName)
                .Map(dest => dest.url, src => src.url);

            config.NewConfig<(string key, ConfirmEmailRequest otp), ConfirmEmailCommand>()
                .Map(dest => dest.Otp, src => src.otp.otp)
                .Map(dest => dest.hashedUserId, src => src.key);

            config.NewConfig<ResendConfirmationEmailRequest, ResendConfirmationEmailQuery>()
                .Map(dest => dest.Email, src => src.Email);

            config.NewConfig<ConfirmEmailResult, ConfirmEmailResponse>()
                .Map(dest => dest.Status, src => src.Status)
                .Map(dest => dest.Message, src => src.Message)
                .Map(dest => dest.User, src => src.User);

            config.NewConfig<ConfirmEmailUserResult, ConfirmEmailUserResponse>()
                .Map(dest => dest.Email, src => src.Email)
                .Map(dest => dest.Id, src => src.Id)
                .Map(dest => dest.IsEmailConfirmed, src => src.IsEmailConfirmed);

            config.NewConfig<ForgetPasswordRequest, ForgetPasswordQuery>()
                .Map(dest => dest.Email, src => src.Email);


            config.NewConfig<ForgetPasswordResult, ForgetPasswordResponse>()
                .Map(dest => dest.Status, src => src.Status)
                .Map(dest => dest.Message, src => src.Message)
                .Map(dest => dest.Email, src => src.Email)
                .Map(dest => dest.Url, src => src.Url);

            config.NewConfig<(string hashedUserId, ConfirmForgetPwRequest request), ConfirmForgetPwOtpQuery>()
                .Map(dest => dest.Otp, src => src.request.Otp)
                .Map(dest => dest.HashedUserId, src => src.hashedUserId);

            config.NewConfig<(string key, string userId, ChangePwRequest request), ChangePwCommand>()
                .Map(dest => dest.ConfirmPassword, src => src.request.ConfirmPassword)
                .Map(dest => dest.Password, src => src.request.Password)
                .Map(dest => dest.Key, src => src.key)
                .Map(dest => dest.UserId, src => src.userId);

            config.NewConfig<ChangePwResult, ChangePwResponse>()
                .Map(dest => dest.Message, src => src.Message)
                .Map(dest => dest.Status, src => src.Status);

            config.NewConfig<LoginRequest, LoginCommand>()
                .Map(dest => dest.Email, src => src.Email)
                .Map(dest => dest.Password, src => src.Password);

            config.NewConfig<LoginUserResult, LoginUserReponse>()
                .Map(dest => dest.Email, src => src.Email)
                .Map(dest => dest.Id, src => src.Id)
                .Map(dest => dest.Name, src => src.Name)
                .Map(dest => dest.UserName, src => src.UserName);

            config.NewConfig<LoginResult, LoginResponse>()
                .Map(dest => dest.User, src => src.User)
                .Map(dest => dest.AccessToken, src => src.AccessToken)
                .Map(dest => dest.RefreshToken, src => src.RefreshToken)
                .Map(dest => dest.ExpiresIn, src => src.ExpiresIn)
                .Map(dest => dest.TokenType, src => src.TokenType)
                .Map(dest => dest.IdToken, src => src.IdToken);

            config.NewConfig<RefreshTokenRequest, RefreshTokenCommand>()
                .Map(dest => dest.RefreshToken, src => src.RefreshToken);

            config.NewConfig<RefreshTokenResult, RefreshTokenReponse>()
                .Map(dest => dest.AccessToken, src => src.AccessToken)
                .Map(dest => dest.RefreshToken, src => src.RefreshToken)
                .Map(dest => dest.ExpiresIn, src => src.ExpiresIn)
                .Map(dest => dest.TokenType, src => src.TokenType)
                .Map(dest => dest.IdToken, src => src.IdToken);

            config.NewConfig<LogoutRequest, LogoutCommand>()
                .Map(dest => dest.AccessToken, src => src.AccessToken)
                .Map(dest => dest.RefreshToken, src => src.RefreshToken);

            config.NewConfig<LogoutResult, LogoutResponse>()
                .Map(dest => dest.Status, src => src.Status)
                .Map(dest => dest.Message, src => src.Message);

            config.NewConfig<GetAllInfoLoginsResult, GetAllInfoLoginsResponse>()
                .Map(dest => dest.Access, src => src.Access)
                .Map(dest => dest.Count, src => src.Count)
                .Map(dest => dest.UserId, src => src.UserId);

            config.NewConfig<GetAllInfoLoginsAccessResult, GetAllInfoLoginsAccessResponse>()
                .Map(dest => dest.AccessToken, src => src.AccessToken)
                .Map(dest => dest.RefreshToken, src => src.RefreshToken)
                .Map(dest => dest.StatusHashed, src => src.StatusHashed);

            config.NewConfig<(string UserId, string AccessToken,RevocationLoginRequest request), RevocationLoginCommand>()
                .Map(dest => dest.UserId, src => src.UserId)
                .Map(dest => dest.RefreshToken, src => src.request.RefreshToken)
                .Map(dest => dest.AccessToken, src => src.AccessToken);

            config.NewConfig<RevocationLoginResult, RevocationLoginReponse>()
                .Map(dest => dest.Message, src => src.Message)
                .Map(dest => dest.Status, src => src.Status);

            config.NewConfig<RefreshGoogleRequest, RefreshTokenGoogleCommand>()
                .Map(dest => dest.RefreshToken, src => src.RefreshToken);
        }
    }
}
