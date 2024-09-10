using ErrorOr;

namespace Identity.Domain.Common.Errors
{
    public static partial class Errors
    {
        public static class User
        {
            public static Error DuplicateEmail => Error.Conflict(
                code: "User.DuplicateEmail",
                description: "Email is already in use"
                );
            public static Error RegiterError => Error.Unexpected(
                code: "User.RegiterError",
                description: "Common Error"
                );
            public static Error NotFoundUser => Error.NotFound(
                code: "User.NotFoundUser",
                description: "User not found"
                );
            public static Error EmailConfirmed => Error.Conflict(
                code: "User.EmailConfirmed",
                description: "Email is already confirmed"
                );
            public static Error EmailUnConfirm => Error.Conflict(
                code: "User.EmailUnConfirm",
                description: "This email is not verified."
                );
        }
    }
}
