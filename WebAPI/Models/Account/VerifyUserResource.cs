using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPI.Models.Account
{
    public class VerifyUserResource
    {
        public string UserName { get; set; }
        public string Phone { get; set; }
        public string OTP { get; set; }
    }
}
