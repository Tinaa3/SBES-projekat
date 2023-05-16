using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using Contract;
using SecurityException = Contract.SecurityException;

namespace Client
{
    public class WCFClient : ChannelFactory<IServiceManagment>, IServiceManagment, IDisposable
    {
		IServiceManagment factory;

        public WCFClient(Binding binding, string remoteAddress) : base(binding, remoteAddress)
        {
            factory = this.CreateChannel();
        }
        public WCFClient(Binding binding, EndpointAddress remoteAddress) : base(binding, remoteAddress)
        {
            factory = this.CreateChannel();
        }

        public bool Connect(byte[] encryptedSessionKey)
        {
            bool connected = false;
            try
            {
                connected = factory.Connect(encryptedSessionKey);

            }
            catch (FaultException<SecurityException> sec)
            {
                Console.WriteLine(sec.Message);

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return connected;
        }

        public bool StartNewService(byte[] encryptedMessage)
        {
            try
            {
                return factory.StartNewService(encryptedMessage);
            }
            catch (FaultException<SecurityException> sec)
            {
                Console.WriteLine(sec.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return false;
        }

        public bool AddRule(string group, string protocol = "", int port = -1)
        {
            bool ruleAdded = false;
            try
            {
                ruleAdded=factory.AddRule(group, protocol, port);
                
            }
            catch (FaultException<SecurityException> sec)
            {
                //Console.WriteLine("greska klijenr1");
                Console.WriteLine(sec.Message);
            }
            catch (Exception e)
            {
                //Console.WriteLine("greska klijenr2");
                Console.WriteLine(e.Message);
            }

            return ruleAdded;
        }

        public bool RemoveRule(string group, string protocol = "", int port = -1)
        {
            bool ruleRemoved=false;
            try
            {
               ruleRemoved = factory.RemoveRule(group, protocol, port);
                
            }
            catch (FaultException<SecurityException> sec)
            {
                Console.WriteLine(sec.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return ruleRemoved;
        }

        public void Dispose()
        {
            if (factory != null)
            {
                factory = null;
            }

            this.Close();
        }
    }
}