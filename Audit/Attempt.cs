using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Audit
{
    public class Attempt
    {
        private string protocol;
        private string port;
        private int numberOfAttempt;
        private DateTime time;

        public Attempt(string protocol, string port, int numberOfAttempt, DateTime time)
        {
            this.Protocol = protocol;
            this.Port = port;
            this.NumberOfAttempt = numberOfAttempt;
            this.Time = time;
        }

        public string Protocol { get => protocol; set => protocol = value; }
        public string Port { get => port; set => port = value; }
        public int NumberOfAttempt { get => numberOfAttempt; set => numberOfAttempt = value; }
        public DateTime Time { get => time; set => time = value; }

        public bool CheckTime(DateTime newtime, int numberOfSeconds)
        {
            if (((int)(newtime - time).TotalSeconds) < numberOfSeconds)
            {
                time = newtime;
                numberOfAttempt++;
                return true;
            }

            return false;
        }

    }
}
