using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Contract
{
    [ServiceContract]
    public interface IAuditContract
    {
        [OperationContract]
        void TestCommunication();

        [OperationContract]
        void LogAuthenticationSuccess(string username);

        [OperationContract]
        void LogAuthorizationSuccess(string username, string serviceName);

        [OperationContract]
        void LogAuthorizationFailed(string username, string serviceName, string reason);

        [OperationContract]
        void LogServiceStarted(string username);

        [OperationContract]
        void LogServiceStartDenied(string username, string protocol, string port, string reason);

        [OperationContract]
        void BlacklistFaultedState();

        [OperationContract]
        void BlacklistRuleAdded(string username, string group, string protocol, string port);

        [OperationContract]
        void BlacklistRuleRemoved(string username, string group, string protocol, string port);

    }
}
