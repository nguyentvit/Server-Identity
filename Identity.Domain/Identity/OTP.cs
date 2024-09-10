using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Identity.Domain.Identity
{
    public class OTP
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string UserId { get; set; } = null!;
        [ForeignKey("UserId")]
        public ApplicationUser User { get; set; } = null!;
        [Required]
        public string Code { get; set; } = null!;
        [Required]
        public DateTime ExpiryTime { get; set; }    
        public bool IsUsed { get; set; }
    }
}
