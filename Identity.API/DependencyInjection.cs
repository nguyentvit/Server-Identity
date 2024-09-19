using Asp.Versioning;
using Identity.API.Common.Attributes;
using Identity.API.Common.Errors;
using Identity.API.Common.Mapping;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using System.Threading.RateLimiting;

namespace Identity.API
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddPresentation(this IServiceCollection services)
        {
            services.AddControllers();

            services.AddApiVersioning(options =>
            {
                options.ApiVersionReader = new UrlSegmentApiVersionReader();
                options.DefaultApiVersion = new ApiVersion(1, 0);
                options.AssumeDefaultVersionWhenUnspecified = true;
            }).AddApiExplorer(options =>
            {
                options.GroupNameFormat = "'v'VVV";
                options.SubstituteApiVersionInUrl = true;
            });
            services.AddMappings();
            services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo()
                {
                    Title = "Identity Web API",
                    Version = "1.0"
                });
                options.SwaggerDoc("v2", new Microsoft.OpenApi.Models.OpenApiInfo()
                {
                    Title = "Identity Web API",
                    Version = "2.0"
                });
            });

            services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

                options.AddPolicy("fixed", httpContext => RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: httpContext.Connection.RemoteIpAddress?.ToString(),
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 5,
                        Window = TimeSpan.FromSeconds(20)
                    }
                    ));
            });
            

            services.AddSingleton<ProblemDetailsFactory, ProblemDetailFactory>();

            services.AddTransient<IAuthorizationHandler, TokenBlacklistHandler>();
            services.AddHttpContextAccessor();

            services.AddAuthorization(options =>
            {
                options.AddPolicy("BlacklistPolicy", policy =>
                    policy.Requirements.Add(new TokenBlacklistRequirement()));
            });

            services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", builder =>
                {
                    builder.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyMethod();
                });
            });

            
            

            return services;
        }
    }
}
