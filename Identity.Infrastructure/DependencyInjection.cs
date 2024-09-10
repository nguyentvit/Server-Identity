using Identity.Application.Common.Persistence;
using Identity.Application.Data;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Models;
using Identity.Domain.Identity;
using Identity.Infrastructure.Persistence;
using Identity.Infrastructure.Persistence.Repository;
using Identity.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Identity.Infrastructure.Common.Interfaces;
using StackExchange.Redis;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.Google;
using Identity.Infrastructure.Common;

namespace Identity.Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, ConfigurationManager configuration)
        {
            services.AddIdentity(configuration);
            services.AddEmailSender(configuration);
            services.AddAuth(configuration);
            services.AddRedis(configuration);

            

            // Đăng ký IHttpContextAccessor
            services.AddHttpContextAccessor();

            services.AddScoped<IEmailSender, EmailSender>();

            services.AddSingleton<IOTPService, OTPService>();
            services.AddSingleton<ITokenProvider, TokenProvider>();

            //services.AddScoped<IOTPRepository, OTPRepository>();
            services.AddScoped<IOTPQueryRepository, OTPQueryRepository>();
            services.AddScoped<IOTPCommandRepository, OTPCommandRepository>();

            services.AddScoped<IOTPPwCommandRepository, OTPPwCommandRepository>();
            services.AddScoped<IOTPPwQueryRepository, OTPPwQueryRepository>();

            services.AddScoped<IApplicationUserQueryRepository, ApplicationUserQueryRepository>();

            services.AddScoped<IUnitOfWork, UnitOfWork>();

            services.AddScoped<IPersistedGrantRepository, PersistedGrantRepository>();

            services.AddScoped<IPersistedGrantService, PersistedGrantService>();

            services.AddSingleton<IRefreshTokenHasher, RefreshTokenHasher>();
            //services.AddScoped<IOTPPwRepository, OTPPwRepository>();



            services.AddSingleton<ISqlConnectionFactory>(provider =>
            {
                var connection = configuration.GetConnectionString("SqlConnection");
                return new SqlConnectionFactory(connection);
            });

            return services;
        }
        public static IServiceCollection AddIdentity(this IServiceCollection services, ConfigurationManager configuration)
        {
            var connection = configuration.GetConnectionString("DefaultConnection");
            var migrationsAssembly = typeof(DependencyInjection).Assembly.GetName().FullName;
            services.AddDbContext<IdentityDbContext>(options =>
            {
                options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
            });


            services.Configure<DataProtectionTokenProviderOptions>(options =>
            {
                options.TokenLifespan = TimeSpan.FromMinutes(15);
            });

            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // configure token
                //options.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultProvider;
                //options.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultProvider;


                // configure password
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 1;

                // configure signin
                options.SignIn.RequireConfirmedEmail = true;
                options.SignIn.RequireConfirmedAccount = true;
            })
                .AddEntityFrameworkStores<IdentityDbContext>()
                .AddDefaultTokenProviders();

            services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
                options.EmitStaticAudienceClaim = true;
            })
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = db =>
                        db.UseSqlServer(connection,
                        sql => sql.MigrationsAssembly(migrationsAssembly));
                })
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = db =>
                    db.UseSqlServer(connection,
                    sql => sql.MigrationsAssembly(migrationsAssembly));
                })
                .AddAspNetIdentity<ApplicationUser>()
                .AddExtensionGrantValidator<TokenExchangeGrantValidator>()
                .AddProfileService<CustomProfileService>()
                .AddDeveloperSigningCredential()
                ;

            services.AddTransient<UserManager<ApplicationUser>, CustomUserManager>();
            services.AddTransient<IPasswordHasher<ApplicationUser>, CustomPasswordHasher<ApplicationUser>>();

            return services;
        }
        public static IServiceCollection AddEmailSender(this IServiceCollection services, ConfigurationManager configuration)
        {
            var smtpSettings = new SmtpSettings();
            configuration.Bind(SmtpSettings.SectionName, smtpSettings);
            services.AddSingleton(Options.Create(smtpSettings));

            services.AddFluentEmail(smtpSettings.FromEmail, smtpSettings.FromName)
                .AddSmtpSender(smtpSettings.Host, smtpSettings.Port, smtpSettings.UserName, smtpSettings.Password)
                .AddRazorRenderer();
            return services;
        }
        public static IServiceCollection AddAuth(this IServiceCollection services, ConfigurationManager configuration)
        {
            services.AddAuthentication(
                options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }
            )
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.Authority = "https://localhost:7100/";
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        ValidateIssuer = true,
                        ValidIssuer = "https://localhost:7100/",
                        ValidateAudience = true,
                        ValidAudience = "https://localhost:7100/resources",
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,
                        IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                        {
                            var client = new HttpClient();
                            var response = client.GetStringAsync("https://localhost:7100/.well-known/openid-configuration/jwks").Result;
                            var keys = JsonConvert.DeserializeObject<JsonWebKeySet>(response).Keys;
                            return keys;
                        }
                    };
                })
                .AddCookie()
                .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
                {
                    options.ClientId = "54512677689-2fi560s0sleddn285cmaaa7vjr6fcrhl.apps.googleusercontent.com";
                    options.ClientSecret = "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";
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                    options.AccessType = "offline";

                    options.CallbackPath = new PathString("/signin-google");

                    options.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/auth";
                    options.TokenEndpoint = "https://accounts.google.com/o/oauth2/token";
                    options.UserInformationEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo";

                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("email");

                    options.SaveTokens = true;

                    options.Events.OnRedirectToAuthorizationEndpoint = context =>
                    {
                        var uriBuilder = new UriBuilder(context.RedirectUri);
                        var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);

                        query["access_type"] = "offline";
                        query["response_type"] = "code";
                        uriBuilder.Query = query.ToString();

                        context.Response.Redirect(uriBuilder.ToString());
                        return Task.CompletedTask;
                    };
                })
                .AddOpenIdConnect("oidc", options =>
                {
                    options.Authority = "https://localhost:7100/";
                    options.ClientId = "web-client";
                    options.ClientSecret = "web-client-secret";
                    options.ResponseType = "code";
                    options.SaveTokens = true;
                    options.CallbackPath = "/signin-google";
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("email");

                });

            return services;
        }
        public static IServiceCollection AddRedis(this IServiceCollection services, ConfigurationManager configuration)
        {
            var redisConfiguration = configuration.GetSection("RedisConfiguration:ConnectionString").Value;
            var options = ConfigurationOptions.Parse(redisConfiguration);
            options.AbortOnConnectFail = false;


            bool redisEnabled = configuration.GetSection("RedisConfiguration:Enabled").Value == "True";

            if (redisEnabled)
            {
                var connectionMultiplexer = ConnectionMultiplexer.Connect(options);
                services.AddSingleton<IConnectionMultiplexer>(connectionMultiplexer);
                services.AddStackExchangeRedisCache(options =>
                {
                    options.Configuration = redisConfiguration;
                });
                services.AddScoped<ITokenBlacklistService, RedisTokenBlacklistService>();
                services.AddScoped<ITokenWhitelistService, RedisTokenWhitelistService>();

            }

            return services;
        }
    }
    
}
