using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Identity.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class addotppw2 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_OTPPw_AspNetUsers_UserId",
                table: "OTPPw");

            migrationBuilder.DropPrimaryKey(
                name: "PK_OTPPw",
                table: "OTPPw");

            migrationBuilder.RenameTable(
                name: "OTPPw",
                newName: "OTPPws");

            migrationBuilder.RenameIndex(
                name: "IX_OTPPw_UserId",
                table: "OTPPws",
                newName: "IX_OTPPws_UserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_OTPPws",
                table: "OTPPws",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_OTPPws_AspNetUsers_UserId",
                table: "OTPPws",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_OTPPws_AspNetUsers_UserId",
                table: "OTPPws");

            migrationBuilder.DropPrimaryKey(
                name: "PK_OTPPws",
                table: "OTPPws");

            migrationBuilder.RenameTable(
                name: "OTPPws",
                newName: "OTPPw");

            migrationBuilder.RenameIndex(
                name: "IX_OTPPws_UserId",
                table: "OTPPw",
                newName: "IX_OTPPw_UserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_OTPPw",
                table: "OTPPw",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_OTPPw_AspNetUsers_UserId",
                table: "OTPPw",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
