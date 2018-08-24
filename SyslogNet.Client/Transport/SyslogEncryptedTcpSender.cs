using System;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace SyslogNet.Client.Transport
{
	public class SyslogEncryptedTcpSender : SyslogTcpSender
	{
		protected int IOTimeout;
		public Boolean IgnoreTLSChainErrors { get; private set; }

		protected MessageTransfer _messageTransfer;
	    private X509CertificateCollection CertificateCollection = null;

		public override MessageTransfer messageTransfer
		{
			get { return _messageTransfer; }
			set
			{
				if (!value.Equals(MessageTransfer.OctetCounting) && transportStream is SslStream)
				{
					throw new SyslogTransportException("Non-Transparent-Framing can not be used with TLS transport");
				}

				_messageTransfer = value;
			}
		}

	    public SyslogEncryptedTcpSender(string hostname, int port, int timeout = Timeout.Infinite, bool ignoreChainErrors = false) : base(hostname, port)
	    {
	        IOTimeout = timeout;
	        IgnoreTLSChainErrors = ignoreChainErrors;
	        startTLS();
	    }

	    public SyslogEncryptedTcpSender(string hostname, int port, SecurityProtocolType securityProtocolType, X509CertificateCollection certificateCollection = null, int timeout = Timeout.Infinite, bool ignoreChainErrors = false) : base(hostname, port)
	    {
	        System.Net.ServicePointManager.SecurityProtocol = securityProtocolType;
	        CertificateCollection = certificateCollection;
	        IOTimeout = timeout;
	        IgnoreTLSChainErrors = ignoreChainErrors;
	        startTLS();
	    }

		public override void Reconnect()
		{
			base.Reconnect();
			startTLS();
		}


		private void startTLS()
		{
			transportStream = new SslStream(tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate))
			{
				ReadTimeout = IOTimeout,
				WriteTimeout = IOTimeout
			};

            
			// According to RFC 5425 we MUST support TLS 1.2, but this protocol version only implemented in framework 4.5 and Windows Vista+...
			((SslStream)transportStream).AuthenticateAsClient(
				hostname,
				CertificateCollection,
				System.Security.Authentication.SslProtocols.Tls | System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls12,
				false
			);

			if (!((SslStream)transportStream).IsEncrypted)
				throw new SecurityException("Could not establish an encrypted connection");

			messageTransfer = MessageTransfer.OctetCounting;
		}

		private bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
            //if (sslPolicyErrors == SslPolicyErrors.None || (IgnoreTLSChainErrors && sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors))
                return true;

            //CertificateErrorHandler(String.Format("Certificate error: {0}", sslPolicyErrors));
            //return false;
        }

		// Quick and nasty way to avoid logging framework dependency
		public static Action<string> CertificateErrorHandler = err => { };
	}
}
