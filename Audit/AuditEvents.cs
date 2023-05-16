using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Resources;
using System.Text;
using System.Threading.Tasks;

namespace Audit
{
    public enum AuditEventTypes
    {
        AuthenticationSuccess = 0,
        AuthorizationSuccess = 1,
        AuthorizationFailure = 2,
        ServiceStarted = 3,
        ServiceStartDenied = 4,
        DoSAttackDetected = 5,
        BlacklistFaultedState = 6,
        BlacklistRuleAdded = 7,
        BlacklistRuleRemoved = 8
    }

    public class AuditEvents
    {
        private static ResourceManager resourceManager = null;
        private static object resourceLock = new object();

        private static ResourceManager ResourceMgr
        {
            get
            {
                lock (resourceLock)
                {
                    if (resourceManager == null)
                    {
                        resourceManager = new ResourceManager(typeof(AuditEventFile).ToString(), Assembly.GetExecutingAssembly());
                    }
                    return resourceManager;
                }
            }
        }

        public static string AuthenticationSuccess
        {
            get
            {
                return ResourceMgr.GetString(AuditEventTypes.AuthenticationSuccess.ToString());
            }
        }

        public static string AuthorizationSuccess
        {
            get
            {
                return ResourceMgr.GetString(AuditEventTypes.AuthorizationSuccess.ToString());
            }
        }

        public static string AuthorizationFailed
        {
            get
            {
                return ResourceMgr.GetString(AuditEventTypes.AuthorizationFailure.ToString());
            }
        }

        public static string ServiceStarted
        {
            get
            {
                return ResourceMgr.GetString(AuditEventTypes.ServiceStarted.ToString());
            }
        }

        public static string ServiceStartDenied
        {
            get
            {
                return ResourceMgr.GetString(AuditEventTypes.ServiceStartDenied.ToString());
            }
        }

        public static string DoSAttackDetected
        {
            get
            {
                return ResourceMgr.GetString(AuditEventTypes.DoSAttackDetected.ToString());
            }
        }  
        
        public static string BlacklistFaultedState
        {
            get
            {
                return ResourceMgr.GetString(AuditEventTypes.BlacklistFaultedState.ToString());
            }
        }

        public static string BlacklistRuleAdded
        {
            get
            {
                return ResourceMgr.GetString(AuditEventTypes.BlacklistRuleAdded.ToString());
            }
        }

        public static string BlacklistRuleRemoved
        {
            get
            {
                return ResourceMgr.GetString(AuditEventTypes.BlacklistRuleRemoved.ToString());
            }
        }



    }
}
