using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Contract
{
    [ServiceContract]
    public interface IServiceManagment
    {
        [OperationContract]
        [FaultContract(typeof(SecurityException))]
        bool Connect(byte[] encryptedSessionKey);

        [OperationContract]
        [FaultContract(typeof(SecurityException))]
        bool StartNewService(byte[] encryptedMessage);

        [OperationContract]
        [FaultContract(typeof(SecurityException))]
        bool AddRule(string group, string protocol = "", int port = -1);

        [OperationContract]
        [FaultContract(typeof(SecurityException))]
        bool RemoveRule(string group, string protocol = "", int port = -1);
    }
}
