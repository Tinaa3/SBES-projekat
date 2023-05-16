using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Contract
{
    [DataContract]
    public class SecurityException
    {
        private string message;

        public SecurityException(string message)
        {
            this.message = message;
        }
        [DataMember]
        public string Message
        {
            get { return message; }
            set { message = value; }
        }
    }
}
