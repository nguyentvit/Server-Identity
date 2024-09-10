using ErrorOr;

namespace Identity.Domain.Common.Errors
{
    public static partial class Errors
    {
        public static class CustomError
        {
            public static Error ErrorCanChance => Error.Conflict(
                code: "Common Error",
                description: "Common Error"
                );
        }
    }
}
