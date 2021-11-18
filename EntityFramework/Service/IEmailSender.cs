using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EntityFramework.Service
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string msg);
    }
}
