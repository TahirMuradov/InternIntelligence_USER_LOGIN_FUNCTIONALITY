﻿namespace InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model.DTOs
{
    public class RegisterDTO
    {
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }

        public string Username { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
    }
}
