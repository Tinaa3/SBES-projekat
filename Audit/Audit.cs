using Microsoft.SqlServer.Server;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Audit
{
    public class Audit : IDisposable
    {
        private static EventLog customLog = null;
        const string SourceName = "ServiceManager.Audit";
        const string LogName = "ServiceManagerLogs";

        static Audit()
        {
            try
            {
                if (!EventLog.SourceExists(SourceName))
                {
                    EventLog.CreateEventSource(SourceName, LogName);
                }
                customLog = new EventLog(LogName, Environment.MachineName, SourceName);
            }
            catch (Exception e)
            {
                customLog = null;
                Console.WriteLine("Error while trying to create log handle. Error = {0}", e.Message);
            }
        }

        public static void AuthenticationSuccess(string userName)
        {
            if (customLog != null)
            {
                string UserAuthenticationSuccess = AuditEvents.AuthenticationSuccess;
                string message = String.Format(UserAuthenticationSuccess, userName);
                customLog.WriteEntry(message);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.AuthenticationSuccess));
            }
        }

        public static void AuthorizationSuccess(string userName, string serviceName)
        {
            if (customLog != null)
            {
                string AuthorizationSuccess = AuditEvents.AuthorizationSuccess;
                string message = String.Format(AuthorizationSuccess, userName, serviceName);
                customLog.WriteEntry(message);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.AuthorizationSuccess));
            }
        }

        public static void AuthorizationFailed(string userName, string serviceName, string reason)
        {
            if (customLog != null)
            {
                string AuthorizationFailed = AuditEvents.AuthorizationFailed;
                string message = String.Format(AuthorizationFailed, userName, serviceName, reason);
                customLog.WriteEntry(message, EventLogEntryType.Warning);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.AuthorizationFailure));
            }
        }

        public static void ServiceStarted(string userName)
        {
            if (customLog != null)
            {
                string ServiceStarted = AuditEvents.ServiceStarted;
                string message = string.Format(ServiceStarted, userName);
                customLog.WriteEntry($"{message}");
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.ServiceStarted));
            }
        }

        public static void ServiceStartDenied(string userName, string protocol, string port)
        {
            if (customLog != null)
            {
                string ServiceStartDeined = AuditEvents.ServiceStartDenied;

                string messagePart = string.Empty;
                if (!protocol.Equals(string.Empty) && !port.Equals(string.Empty))
                {
                    messagePart = string.Format($"with protocol:{protocol} on port:{port}");
                }
                else if (!protocol.Equals(string.Empty))
                {
                    messagePart = string.Format($"with protocol:{protocol}");
                }
                else if (!protocol.Equals(string.Empty))
                {
                    messagePart = string.Format($"on port:{port}");
                }

                string message = string.Format(ServiceStartDeined, userName, messagePart);
                customLog.WriteEntry(message, EventLogEntryType.Warning);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                               (int)AuditEventTypes.ServiceStartDenied));
            }
        }

        public static void DoSAttackDetected(string userName)
        {
            if(customLog != null)
            {
                string DoSAttackDetected = AuditEvents.DoSAttackDetected;
                string message = string.Format(DoSAttackDetected, userName);
                customLog.WriteEntry(message, EventLogEntryType.Error);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.DoSAttackDetected));
            }
        }

        public static void BlacklistFaultedState()
        {
            if (customLog != null)
            {
                string BlacklistFaultedState = AuditEvents.BlacklistFaultedState;
                customLog.WriteEntry(BlacklistFaultedState, EventLogEntryType.Error);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.BlacklistFaultedState));
            }
        }

        public static void BlacklistRuleAdded(string userName, string group, string protocol, string port)
        {
            if (customLog != null)
            {
                string BlacklistRuleAdded = AuditEvents.BlacklistRuleAdded;

                string messagePart = string.Empty;
                if (!protocol.Equals(string.Empty) && !port.Equals(string.Empty))
                    messagePart = String.Format("with protocol:{0} on port:{1}", protocol, port);
                else if (!protocol.Equals(string.Empty))
                    messagePart = String.Format("with protocol:{0}", protocol);
                else if (!port.Equals(string.Empty))
                    messagePart = String.Format("on port:{0}", port);

                string message = String.Format(BlacklistRuleAdded, userName, group, messagePart);
                customLog.WriteEntry(message, EventLogEntryType.Information);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.ServiceStartDenied));
            }
        }

        public static void BlacklistRuleRemoved(string userName, string group, string protocol, string port)
        {
            if (customLog != null)
            {
                string BlacklistRuleRemoved = AuditEvents.BlacklistRuleRemoved;

                string messagePart = string.Empty;
                if (!protocol.Equals(string.Empty) && !port.Equals(string.Empty))
                    messagePart = String.Format("with protocol:{0} on port:{1}", protocol, port);
                else if (!protocol.Equals(string.Empty))
                    messagePart = String.Format("with protocol:{0}", protocol);
                else if (!port.Equals(string.Empty))
                    messagePart = String.Format("on port:{0}", port);

                string message = String.Format(BlacklistRuleRemoved, userName, group, messagePart);
                customLog.WriteEntry(message, EventLogEntryType.Information);
            }
            else
            {
                throw new ArgumentException(string.Format("Error while trying to write event (eventid = {0}) to event log.",
                                            (int)AuditEventTypes.ServiceStartDenied));
            }
        }

        public void Dispose()
        {
            if (customLog != null)
            {
                customLog.Dispose();
                customLog = null;
            }
        }
    }
}
